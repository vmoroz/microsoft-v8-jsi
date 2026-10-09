// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "v8host_router.h"
#include <algorithm>
#include <chrono>
#include <cstring>

namespace v8host::coordinator {
namespace {
constexpr auto kCancelFallbackTimeout = std::chrono::seconds(5);
constexpr auto kPostRetryInitial = std::chrono::milliseconds(10);
constexpr auto kPostRetryCap = std::chrono::milliseconds(100);
constexpr unsigned kPostRetryAttempts = 16;
}

Connection::Connection() {
  out_wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
  stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  worker_wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
}
Connection::~Connection() {
  Stop();
  JoinWriter();
  ClearOutput();
  sessions.clear();
  retired_sessions.clear();
  if (out_wake)
    ::CloseHandle(out_wake);
  if (stop)
    ::CloseHandle(stop);
  if (worker_wake)
    ::CloseHandle(worker_wake);
}
void Connection::Stop() {
  if (stop)
    ::SetEvent(stop);
  if (out_wake)
    ::SetEvent(out_wake);
}
namespace {
bool Reserve(std::atomic<size_t> &ledger, size_t bytes, size_t limit) {
  size_t current = ledger.load(std::memory_order_relaxed);
  do {
    if (current > limit || bytes > limit - current)
      return false;
  } while (!ledger.compare_exchange_weak(current, current + bytes));
  return true;
}
}
OutputCredit::OutputCredit(OutputCredit &&other) noexcept { *this = std::move(other); }
OutputCredit &OutputCredit::operator=(OutputCredit &&other) noexcept {
  if (this != &other) {
    Reset();
    conn = other.conn; relay = std::move(other.relay); bytes = other.bytes;
    other.conn = nullptr; other.bytes = 0;
  }
  return *this;
}
OutputCredit::~OutputCredit() { Reset(); }
void OutputCredit::Reset() {
  if (!conn) return;
  if (relay) {
    relay->bytes.fetch_sub(bytes);
    conn->out_relay_bytes.fetch_sub(bytes);
  } else {
    conn->out_control_bytes.fetch_sub(bytes);
    conn->out_control_requests.fetch_sub(1);
  }
  ::SetEvent(conn->worker_wake);
  conn = nullptr; bytes = 0; relay.reset();
}
OutputCredit Connection::ChargeOutput(size_t bytes, std::shared_ptr<RelayLedger> relay) {
  OutputCredit credit;
  if (::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return credit;
  if (relay) {
    if (relay->failed.load()) return credit;
    if (!Reserve(relay->bytes, bytes, protocol::kMaxQueuedRelayBytesPerRun)) {
      relay->failed = true;
      ::SetEvent(worker_wake);
      return credit;
    }
    if (!Reserve(out_relay_bytes, bytes, protocol::kMaxQueuedRelayBytesPerConnection)) {
      relay->bytes.fetch_sub(bytes);
      Stop();
      return credit;
    }
  } else {
    if (!Reserve(out_control_requests, 1, protocol::kMaxControlQueueRequests)) {
      Stop(); return credit;
    }
    if (!Reserve(out_control_bytes, bytes, protocol::kMaxControlQueueBytes)) {
      out_control_requests.fetch_sub(1);
      Stop(); return credit;
    }
  }
  credit.conn = this; credit.bytes = bytes; credit.relay = std::move(relay);
  return credit;
}
bool Connection::Enqueue(std::vector<uint8_t> frame, OutputCredit credit) {
  if (!credit.conn) credit = ChargeOutput(frame.size());
  if (!credit.conn) return false;
  if (credit.conn != this || credit.bytes != frame.size()) { Stop(); return false; }
  std::lock_guard<std::mutex> lock(out_mutex);
  if (!out_wake || !stop || ::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return false;
  out_queue.push_back({std::move(frame), std::move(credit)});
  ::SetEvent(out_wake);
  return true;
}
bool Connection::TakeOutput(std::vector<uint8_t> *frame) {
  std::lock_guard<std::mutex> lock(out_mutex);
  if (out_queue.empty() || in_flight_.conn) return false;
  *frame = std::move(out_queue.front().bytes);
  in_flight_ = std::move(out_queue.front().credit);
  out_queue.pop_front();
  return true;
}
void Connection::CompleteOutput(size_t bytes) {
  std::lock_guard<std::mutex> lock(out_mutex);
  if (in_flight_.conn && bytes == in_flight_.bytes) in_flight_.Reset();
  out_drained_.notify_all();
}
void Connection::ClearOutput() {
  std::lock_guard<std::mutex> lock(out_mutex);
  out_queue.clear();
  in_flight_.Reset();
  out_drained_.notify_all();
}
bool Connection::DrainOutput(DWORD timeout_ms) {
  std::unique_lock<std::mutex> lock(out_mutex);
  return out_drained_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
    return out_queue.empty() && !in_flight_.conn;
  });
}
namespace {
bool Transfer(Connection &conn, bool write, void *data, DWORD capacity, DWORD *transferred, DWORD timeout_ms) {
  OVERLAPPED ov = {};
  ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ov.hEvent)
    return false;
#if defined(V8HOST_ROUTER_TESTING)
  ++conn.active_io;
#endif
  BOOL started = write ? ::WriteFile(conn.pipe, data, capacity, nullptr, &ov)
                       : ::ReadFile(conn.pipe, data, capacity, nullptr, &ov);
  bool pending = !started && ::GetLastError() == ERROR_IO_PENDING;
  bool ok = false;
  if (started) {
#if defined(V8HOST_ROUTER_TESTING)
    if (!write)
      ++conn.inline_reads;
#endif
    ok = ::GetOverlappedResult(conn.pipe, &ov, transferred, FALSE) != FALSE;
  } else if (pending) {
#if defined(V8HOST_ROUTER_TESTING)
    HANDLE barrier = write ? conn.write_pending : conn.read_pending;
    if (barrier)
      ::SetEvent(barrier);
#endif
    HANDLE waits[] = {conn.stop, ov.hEvent, conn.worker_wake};
    for (;;) {
      const DWORD delay = !write && conn.dispatcher ? conn.dispatcher->WakeDelay(conn, timeout_ms) : timeout_ms;
      DWORD result = ::WaitForMultipleObjects(write ? 2 : 3, waits, FALSE, delay);
      if (result == WAIT_TIMEOUT && !write && conn.dispatcher) {
        conn.dispatcher->Pump(conn);
        if (delay != timeout_ms)
          continue;
      }
      if (result == WAIT_OBJECT_0 + 2 && conn.dispatcher) {
        conn.dispatcher->Pump(conn);
        continue;
      }
      if (result == WAIT_OBJECT_0 + 1) {
        ok = ::GetOverlappedResult(conn.pipe, &ov, transferred, FALSE) != FALSE;
        pending = false;
      }
      break;
    }
  }
  if (pending) {
    ::CancelIoEx(conn.pipe, &ov);
    ::GetOverlappedResult(conn.pipe, &ov, transferred, TRUE);
  }
  ::CloseHandle(ov.hEvent);
#if defined(V8HOST_ROUTER_TESTING)
  --conn.active_io;
#endif
  return ok && (!write || *transferred == capacity);
}
} // namespace
bool Connection::ReadsPaused() const {
  return out_control_requests >= protocol::kMaxControlQueueRequests - 1 ||
      out_control_bytes > protocol::kMaxControlQueueBytes - protocol::kMaxFrameSize ||
      out_relay_bytes > protocol::kMaxQueuedRelayBytesPerConnection - protocol::kMaxFrameSize;
}
bool Connection::CompleteZero() const {
  // Called on the strand after I/O and callback borrowers have joined.
  return sessions.empty() && retired_sessions.empty() && in_relay_bytes == 0 &&
      out_relay_bytes == 0 && out_control_bytes == 0 && out_control_requests == 0 && !writer_ && !dispatcher;
}
bool Connection::ReadFrame(uint8_t *buffer, DWORD capacity, DWORD *size, DWORD timeout_ms) {
  if (!stop || ::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0)
    return false;
  bool paused = false;
  const auto pause_begin = std::chrono::steady_clock::now();
  while (dispatcher && ReadsPaused()) {
#if defined(V8HOST_ROUTER_TESTING)
    if (read_paused) ::SetEvent(read_paused);
#endif
    paused = true;
    dispatcher->Pump(*this);
    if (!ReadsPaused()) break;
    // No read is outstanding here. Probe pipe loss even if the writer is idle;
    // a held client process also wakes teardown immediately on client death.
    if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, nullptr, nullptr)) return false;
    HANDLE waits[] = {stop, worker_wake, peer.process()};
    DWORD budget = timeout_ms;
    if (budget != INFINITE) {
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - pause_begin).count();
      if (elapsed >= budget) return false;
      budget -= static_cast<DWORD>(elapsed);
    }
    const DWORD delay = dispatcher->WakeDelay(*this, (std::min)(budget, DWORD{100}));
    const DWORD result = ::WaitForMultipleObjects(peer.process() ? 3 : 2, waits, FALSE, delay);
    if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 2 || result == WAIT_FAILED) return false;
    if (result == WAIT_TIMEOUT && budget != INFINITE && delay == budget) return false;
  }
#if defined(V8HOST_ROUTER_TESTING)
  if (paused && read_resumed) ::SetEvent(read_resumed);
#else
  (void)paused;
#endif
  if (::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) return false;
  const bool ok = Transfer(*this, false, buffer, capacity, size, timeout_ms);
  if (ok && dispatcher)
    dispatcher->Pump(*this);
  return ok;
}
bool Connection::StartWriter() {
  if (writer_ || !stop || !out_wake)
    return false;
  writer_ = ::CreateThread(nullptr, 0, &WriteTask, this, 0, nullptr);
  return writer_ != nullptr;
}
void Connection::JoinWriter() {
  if (!writer_)
    return;
  ::WaitForSingleObject(writer_, INFINITE);
  ::CloseHandle(writer_);
  writer_ = nullptr;
#if defined(V8HOST_ROUTER_TESTING)
  ++writers_joined;
#endif
}
DWORD WINAPI Connection::WriteTask(void *context) {
  auto &conn = *static_cast<Connection *>(context);
#if defined(V8HOST_ROUTER_TESTING)
  ++conn.writers_started;
  if (conn.writer_release) {
    HANDLE waits[] = {conn.stop, conn.writer_release};
    if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1)
      return 0;
  }
#endif
  HANDLE waits[] = {conn.stop, conn.out_wake};
  while (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
    std::vector<uint8_t> frame;
    while (::WaitForSingleObject(conn.stop, 0) != WAIT_OBJECT_0 && conn.TakeOutput(&frame)) {
      DWORD transferred = 0;
      bool ok = Transfer(conn, true, frame.data(), static_cast<DWORD>(frame.size()), &transferred, 2000);
      conn.CompleteOutput(frame.size());
      if (!ok) {
        conn.Stop();
        return 0;
      }
    }
  }
  return 0;
}
bool Run::TryTerminal(RunState desired) {
  if (!IsTerminal(desired) || !session)
    return false;
  RunState previous = state.load();
  do {
    if (IsTerminal(previous))
      return false;
  } while (!state.compare_exchange_strong(previous, desired));
  Connection *conn = session->conn;
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    auto it = session->runs.find(run_id);
    if (it != session->runs.end() && it->second.get() == this) {
      session->retired_runs.push_back(std::move(it->second));
      session->runs.erase(it);
    }
    if (conn) conn->in_relay_bytes -= queued_relay_bytes;
    held_relays.clear();
    queued_relay_bytes = 0;
    if (session->worker) {
      session->worker->Publish(run_id, {});
      auto &worker = *session->worker;
      if (worker.retry_run_id == run_id && worker.retry_type != v8host::RunEnvelopeType::kCancel) {
        worker.retry_deadline = {}; worker.retry_attempts = 0; worker.retry_run_id = 0;
      }
      if (session->worker->active_run_id == run_id)
        session->worker->active_run_id = 0;
      auto &pending = session->worker->pending_run_ids;
      pending.erase(std::remove(pending.begin(), pending.end(), run_id), pending.end());
    }
  }
#if defined(V8HOST_ROUTER_TESTING)
  if (session->terminal_removed)
    session->terminal_removed();
#endif
  if (conn && desired != RunState::kBrokerLost && desired != RunState::kWorkerExited) {
    protocol::FrameHeader header;
    header.version_major = protocol::kWireVersionMajor;
    header.version_minor = conn->version_minor;
    header.conn_id = conn->conn_id;
    header.session_id = session->session_id;
    header.run_id = run_id;
    if (desired == RunState::kCompleted || desired == RunState::kCancelled) {
      protocol::ResultPayload result;
      result.disposition = desired == RunState::kCompleted ? protocol::ResultDisposition::kCompleted
                                                           : protocol::ResultDisposition::kCancelled;
      conn->Enqueue(protocol::BuildResultFrame(header, result.disposition));
    } else {
      protocol::ErrorPayload failure;
      failure.status_code = error;
      auto frame = protocol::BuildErrorFrame(header, failure);
      header.type = protocol::MessageType::RUN_ERROR;
      header.payload_length = static_cast<uint32_t>(frame.size()) - protocol::kFrameHeaderSize;
      std::vector<uint8_t> encoded;
      protocol::EncodeHeader(header, encoded);
      std::copy(encoded.begin(), encoded.end(), frame.begin());
      conn->Enqueue(std::move(frame));
    }
  }
  return true;
}

namespace {
bool ValidString(const std::string &value) {
  return value.size() <= protocol::kMaxStringBytes &&
      protocol::ValidateUtf8NoNul(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}
bool BareEngine(const std::string &value) {
  return !value.empty() && ValidString(value) && value != "." && value.find("..") == std::string::npos &&
      value.find_first_of("\\/:") == std::string::npos;
}
bool CanonicalSnapshot(const std::string &input, std::wstring root, std::string *out) {
  if (input.empty()) {
    out->clear();
    return true;
  }
  if (!ValidString(input))
    return false;
  int count =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
  if (!count)
    return false;
  std::wstring path(count, L'\0');
  ::MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), path.data(), count);
  std::replace(path.begin(), path.end(), L'/', L'\\');
  if (root.starts_with(L"\\\\?\\"))
    root.erase(0, 4);
  if (root.size() < 3 || root[1] != L':' || root[2] != L'\\')
    return false;
  if (path.front() == L'\\' || path.find_first_of(L"*?\"<>|") != std::wstring::npos)
    return false;
  const bool absolute = path.size() >= 3 && path[1] == L':' && path[2] == L'\\';
  if (path.find(L':', absolute ? 2 : 0) != std::wstring::npos)
    return false;
  // Reject Win32 aliasing and device names, but allow ordinary dot segments.
  size_t pos = absolute ? 3 : 0;
  while (pos < path.size()) {
    size_t end = path.find(L'\\', pos);
    if (end == std::wstring::npos)
      end = path.size();
    std::wstring part = path.substr(pos, end - pos);
    if (part.empty())
      return false;
    if (part != L"." && part != L"..") {
      if (part.back() == L'.' || part.back() == L' ')
        return false;
      for (wchar_t c : part)
        if (c < 32)
          return false;
      auto stem = part.substr(0, part.find(L'.'));
      for (auto &c : stem)
        if (c >= L'a' && c <= L'z')
          c -= L'a' - L'A';
      if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
          (stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) && stem[3] >= L'1' &&
           stem[3] <= L'9'))
        return false;
    }
    pos = end + 1;
  }
  if (path.back() == L'\\')
    return false;
  while (root.size() > 3 && root.back() == L'\\')
    root.pop_back();
  std::wstring joined = absolute ? path : root + L"\\" + path;
  DWORD needed = ::GetFullPathNameW(joined.c_str(), 0, nullptr, nullptr);
  if (!needed)
    return false;
  std::wstring canonical(needed, L'\0');
  DWORD actual = ::GetFullPathNameW(joined.c_str(), needed, canonical.data(), nullptr);
  if (!actual || actual >= needed)
    return false;
  canonical.resize(actual);
  if (!IsStrictDescendant(root, canonical))
    return false;
  count = ::WideCharToMultiByte(
      CP_UTF8,
      WC_ERR_INVALID_CHARS,
      canonical.data(),
      static_cast<int>(canonical.size()),
      nullptr,
      0,
      nullptr,
      nullptr);
  if (!count)
    return false;
  out->resize(count);
  ::WideCharToMultiByte(
      CP_UTF8,
      WC_ERR_INVALID_CHARS,
      canonical.data(),
      static_cast<int>(canonical.size()),
      out->data(),
      count,
      nullptr,
      nullptr);
  return true;
}
protocol::FrameHeader ReplyHeader(const Connection &conn, uint32_t session, uint32_t run = 0) {
  protocol::FrameHeader h;
  h.version_major = protocol::kWireVersionMajor;
  h.version_minor = conn.version_minor;
  h.conn_id = conn.conn_id;
  h.session_id = session;
  h.run_id = run;
  return h;
}
std::vector<uint8_t> Error(protocol::FrameHeader h, protocol::StatusCode status) {
  protocol::ErrorPayload error;
  error.status_code = status;
  return protocol::BuildErrorFrame(h, error);
}
// Caller holds Connection::mutex; removed storage outlives terminal contenders.
void RetireSessionLocked(Connection &conn, uint32_t id, RunState terminal) {
  auto it = conn.sessions.find(id);
  if (it == conn.sessions.end())
    return;
  auto session = std::move(it->second);
  conn.sessions.erase(it);
  std::vector<Run *> runs;
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    session->state = SessionState::kClosing;
    for (auto &[run_id, run] : session->runs) {
      runs.push_back(run.get());
      session->retired_runs.push_back(std::move(run));
    }
    session->runs.clear();
  }
  for (Run *run : runs)
    run->TryTerminal(terminal);
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    session->state = SessionState::kClosed;
  }
  if (session->worker || !session->retired_runs.empty())
    conn.retired_sessions.push_back(std::move(session));
}
} // namespace

uint32_t AllocateId(std::atomic<uint32_t> &next) {
  uint32_t id = next.load();
  do {
    if (!id || id == UINT32_MAX) return 0;
  } while (!next.compare_exchange_weak(id, id + 1));
  return id;
}
bool EnvelopeFits(v8host::RunEnvelopeType type, size_t size) {
  const size_t overhead =
      v8host::kRunEnvelopeHeaderSize + (type == v8host::RunEnvelopeType::kRelay ? sizeof(int32_t) : 0);
  return size <= protocol::kMaxFramePayload - overhead;
}
bool ValidateSessionConfig(const SessionConfig &config, BrokerMode mode) {
  if ((config.broker_mode != 0 && config.broker_mode != 1) || config.broker_mode != static_cast<int32_t>(mode) ||
      (config.tier != kTierUntrusted && config.tier != kTierTrusted) || config.integrity < sbox_integrity_low ||
      config.integrity > sbox_integrity_untrusted || config.delayed_integrity < sbox_integrity_low ||
      config.delayed_integrity > sbox_integrity_untrusted || config.initial_token < sbox_token_lockdown ||
      config.initial_token > sbox_token_restricted_same_access || config.lockdown_token < sbox_token_lockdown ||
      config.lockdown_token > sbox_token_restricted_same_access ||
      (config.tier == kTierUntrusted) != config.prohibit_dynamic_code)
    return false;
  if (config.file_rules.size() > protocol::kMaxFileRules || config.capabilities.size() > protocol::kMaxCapabilities ||
      !ValidString(config.app_container_profile))
    return false;
  for (const auto &rule : config.file_rules)
    if (!ValidString(rule.pattern))
      return false;
  for (const auto &cap : config.capabilities)
    if (!ValidString(cap))
      return false;
  protocol::Writer writer;
  protocol::EncodeCreateSessionPayload(config, writer);
  SessionConfig decoded;
  return protocol::DecodeCreateSessionPayload(writer.buffer().data(), writer.buffer().size(), &decoded);
}
bool PrepareProfile(
    const SessionConfig &config,
    const protocol::StartRunPayload &inputs,
    const std::wstring &payload_directory,
    BoundProfile *out) {
  if (!out || inputs.schema_version != protocol::kMessageSchemaVersion || inputs.tier_override < -1 ||
      inputs.tier_override > kTierTrusted || (!inputs.has_engine_override && !inputs.engine_filename.empty()) ||
      (!inputs.has_snapshot && !inputs.snapshot_path.empty()))
    return false;
  BoundProfile profile;
  profile.effective_tier = inputs.tier_override == -1 ? config.tier : inputs.tier_override;
  if ((profile.effective_tier != kTierUntrusted && profile.effective_tier != kTierTrusted) ||
      (profile.effective_tier == kTierUntrusted) != config.prohibit_dynamic_code)
    return false;
  profile.prohibit_dynamic_code = config.prohibit_dynamic_code;
  profile.engine_dll = inputs.has_engine_override
      ? inputs.engine_filename
      : (profile.effective_tier == kTierUntrusted ? "v8jsisb.dll" : "v8jsi.dll");
  if (!BareEngine(profile.engine_dll) ||
      !CanonicalSnapshot(inputs.has_snapshot ? inputs.snapshot_path : "", payload_directory, &profile.snapshot_path))
    return false;
  V8HostWorkerProfileV1 worker;
  worker.jitless = profile.effective_tier == kTierUntrusted;
  worker.engine_dll = profile.engine_dll;
  worker.snapshot_path = profile.snapshot_path;
  auto bytes = worker.Encode();
  V8HostWorkerProfileV1 decoded;
  if (!V8HostWorkerProfileV1::Decode(bytes.data(), bytes.size(), &decoded))
    return false;
  *out = std::move(profile);
  return true;
}
protocol::StatusCode BindProfile(Session &session, const BoundProfile &profile) {
  std::lock_guard<std::mutex> lock(session.mutex);
  if (session.profile_bound) {
    const auto &bound = session.profile;
    if (bound.effective_tier != profile.effective_tier || bound.engine_dll != profile.engine_dll ||
        bound.snapshot_path != profile.snapshot_path || bound.prohibit_dynamic_code != profile.prohibit_dynamic_code)
      return protocol::StatusCode::ERROR_PROFILE_ALREADY_BOUND;
  } else {
    session.profile = profile;
    session.profile_bound = true;
  }
  return protocol::StatusCode::OK;
}
bool PrepareSpawnConfig(const SessionConfig &config, const BoundProfile &profile, std::vector<uint8_t> *out) {
  if (!out || !ValidateSessionConfig(config, static_cast<BrokerMode>(config.broker_mode)) ||
      profile.prohibit_dynamic_code != config.prohibit_dynamic_code ||
      (profile.effective_tier != kTierUntrusted && profile.effective_tier != kTierTrusted) ||
      (profile.effective_tier == kTierUntrusted) != config.prohibit_dynamic_code)
    return false;
  V8HostSpawnConfigV1 spawn;
  spawn.tier = config.tier;
  spawn.integrity = config.integrity;
  spawn.delayed_integrity = config.delayed_integrity;
  spawn.initial_token = config.initial_token;
  spawn.lockdown_token = config.lockdown_token;
  spawn.prohibit_dynamic_code = config.prohibit_dynamic_code;
  spawn.use_app_container = config.use_app_container;
  spawn.low_privilege_app_container = config.low_privilege_app_container;
  spawn.app_container_profile = config.app_container_profile;
  for (const auto &rule : config.file_rules)
    spawn.file_rules.push_back({rule.readonly, rule.pattern});
  spawn.capabilities = config.capabilities;
  spawn.effective_tier = profile.effective_tier;
  spawn.engine_dll = profile.engine_dll;
  spawn.snapshot_path = profile.snapshot_path;
  auto bytes = spawn.Encode();
  V8HostSpawnConfigV1 decoded;
  if (!V8HostSpawnConfigV1::Decode(bytes.data(), bytes.size(), &decoded))
    return false;
  V8HostWorkerProfileV1 worker;
  worker.jitless = profile.effective_tier == kTierUntrusted;
  worker.engine_dll = profile.engine_dll;
  worker.snapshot_path = profile.snapshot_path;
  auto worker_bytes = worker.Encode();
  V8HostWorkerProfileV1 worker_decoded;
  if (!V8HostWorkerProfileV1::Decode(worker_bytes.data(), worker_bytes.size(), &worker_decoded))
    return false;
  *out = std::move(bytes);
  return true;
}

bool Router::Route(Connection &conn, const uint8_t *data, size_t size) {
  protocol::FrameHeader h;
  const uint8_t *payload = nullptr;
  size_t payload_size = 0;
  if (protocol::DecodeAndValidateFrame(data, size, &h, &payload, &payload_size) != protocol::DecodeStatus::kOk ||
      conn.state != ConnState::kOpen || h.version_major != protocol::kWireVersionMajor ||
      h.version_minor != conn.version_minor || h.conn_id != conn.conn_id)
    return false;
  switch (h.type) {
    case protocol::MessageType::HELLO:
    case protocol::MessageType::HELLO_ACK:
    case protocol::MessageType::CREATE_SESSION:
    case protocol::MessageType::SESSION_READY:
    case protocol::MessageType::START_RUN:
    case protocol::MessageType::CANCEL_RUN:
    case protocol::MessageType::CLOSE_SESSION:
    case protocol::MessageType::ACK:
    case protocol::MessageType::ERROR:
    case protocol::MessageType::WORKER_EXIT:
    case protocol::MessageType::STARTUP_READY:
    case protocol::MessageType::SECURITY_READY:
    case protocol::MessageType::RESULT:
    case protocol::MessageType::RUN_ERROR:
    case protocol::MessageType::RELAY_TO_WORKER:
    case protocol::MessageType::RELAY_FROM_WORKER:
      break;
    default:
      if (!(h.flags & protocol::kFlagMustUnderstand))
        return true;
      if (conn.Enqueue(Error(h, protocol::StatusCode::ERROR_UNSUPPORTED_MESSAGE)))
        conn.state = ConnState::kClosing;
      return false;
  }
  if (h.session_id == UINT32_MAX || h.run_id == UINT32_MAX || h.request_id == UINT32_MAX) {
    conn.Stop(); return false;
  }
  if (!h.session_id) return false;
  const bool relay = h.type == protocol::MessageType::RELAY_TO_WORKER;
  const bool create = h.type == protocol::MessageType::CREATE_SESSION;
  const bool start = h.type == protocol::MessageType::START_RUN;
  const bool cancel = h.type == protocol::MessageType::CANCEL_RUN;
  const bool close = h.type == protocol::MessageType::CLOSE_SESSION;
  if ((!relay && !create && !start && !cancel && !close) || ((create || close) ? h.run_id != 0 : h.run_id == 0) ||
      (relay ? h.request_id != 0 : h.request_id == 0) || ((cancel || close) && payload_size != 0))
    return false;
  if (relay) {
    int32_t kind = 0;
    const uint8_t *body = nullptr;
    size_t body_size = 0;
    if (!protocol::DecodeRelayPayload(payload, payload_size, &kind, &body, &body_size) ||
        (kind != sbox_msg_string && kind != sbox_msg_binary))
      return false;
    Pump(conn);
    auto sit = conn.sessions.find(h.session_id);
    if (sit == conn.sessions.end())
      return true;
    auto &session = *sit->second;
    auto rit = session.runs.find(h.run_id);
    if (rit == session.runs.end())
      return true;
    auto &run = *rit->second;
    v8host::RunEnvelope env;
    env.type = v8host::RunEnvelopeType::kRelay;
    env.run_id = h.run_id;
    env.relay_kind = kind;
    env.payload.assign(body, body + body_size);
    auto bytes = v8host::EncodeRunEnvelope(env);
    if (bytes.size() > protocol::kMaxFramePayload ||
        bytes.size() > protocol::kMaxQueuedRelayBytesPerRun - run.queued_relay_bytes || run.held_relays.size() >= 256) {
      run.error = protocol::StatusCode::ERROR_QUOTA;
      run.TryTerminal(RunState::kFailed);
      if (session.worker && session.worker->engine_busy_run_id == h.run_id) {
        RequestCancel(session, h.run_id);
      }
      return true;
    }
    if (bytes.size() > protocol::kMaxQueuedRelayBytesPerConnection - conn.in_relay_bytes) {
      conn.Stop();
      return false;
    }
    conn.in_relay_bytes += bytes.size();
    run.queued_relay_bytes += static_cast<uint32_t>(bytes.size());
    run.held_relays.push_back(std::move(bytes));
    Dispatch(session);
    Pump(conn);
    return true;
  }
  protocol::RequestIdentity identity{h.type, h.conn_id, h.session_id, h.run_id, h.request_id, h.flags};
  auto classified = conn.request_cache.Classify(identity, payload, payload_size);
  if (classified.classification == protocol::RequestClass::kMismatchedDuplicate)
    return false;
  if (classified.classification == protocol::RequestClass::kExactDuplicate) {
    auto response = *classified.cached_response;
    return conn.Enqueue(std::move(response));
  }
  if (classified.classification == protocol::RequestClass::kStale)
    return conn.Enqueue(Error(h, protocol::StatusCode::ERROR_STALE_REQUEST));
  std::vector<uint8_t> response;
  bool ready = false;
  Session *admitted_session = nullptr;
  Run *admitted_run = nullptr;
  bool needs_spawn = false;
  if (create) {
    Reclaim(conn, false);
    SessionConfig config;
    if (!protocol::DecodeCreateSessionPayload(payload, payload_size, &config))
      return false;
    std::lock_guard<std::mutex> lock(conn.mutex);
    if (conn.sessions.contains(h.session_id))
      return false;
    if (!ValidateSessionConfig(config, mode_) || h.session_id <= conn.highest_session_id) {
      response = Error(h, protocol::StatusCode::ERROR_BAD_STATE);
    } else if (conn.sessions.size() + conn.retired_sessions.size() >= protocol::kMaxSessionsPerConnection) {
      response = Error(h, protocol::StatusCode::ERROR_QUOTA);
    } else {
      auto session = std::make_unique<Session>();
      session->session_id = h.session_id;
      session->conn = &conn;
      session->config = std::move(config);
      conn.sessions.emplace(h.session_id, std::move(session));
      conn.highest_session_id = h.session_id;
      response = protocol::BuildAckFrame(h);
      ready = true;
    }
  } else if (start) {
    protocol::StartRunPayload inputs;
    if (!protocol::DecodeStartRunPayload(payload, payload_size, &inputs))
      return false;
    auto it = conn.sessions.find(h.session_id);
    BoundProfile profile;
    bool prepared =
        it != conn.sessions.end() && PrepareProfile(it->second->config, inputs, payload_directory_, &profile);
    if (!prepared && it != conn.sessions.end() && it->second->profile_bound && inputs.tier_override >= 0 &&
        inputs.tier_override <= kTierTrusted && inputs.tier_override != it->second->profile.effective_tier) {
      auto normalized = inputs;
      normalized.tier_override = -1;
      prepared = PrepareProfile(it->second->config, normalized, payload_directory_, &profile);
      if (prepared) {
        profile = it->second->profile;
        profile.effective_tier = inputs.tier_override;
      }
    }
    if (it == conn.sessions.end() || !broker_ || !api_ || h.run_id <= it->second->highest_run_id || !prepared) {
      response = Error(h, protocol::StatusCode::ERROR_BAD_STATE);
    } else if (it->second->runs.size() >= protocol::kMaxInFlightRunsPerSession) {
      response = Error(h, protocol::StatusCode::ERROR_QUOTA);
    } else {
      auto &session = *it->second;
      auto owned = std::make_unique<Run>();
      owned->session = &session;
      owned->run_id = h.run_id;
      owned->guest = std::move(inputs.guest_payload);
      owned->state = RunState::kStartPending;
      owned->error = EnvelopeFits(v8host::RunEnvelopeType::kStart, owned->guest.size())
          ? BindProfile(session, profile)
          : protocol::StatusCode::ERROR_QUOTA;
      admitted_run = owned.get();
      session.runs.emplace(h.run_id, std::move(owned));
      session.highest_run_id = h.run_id;
      admitted_session = &session;
      if (admitted_run->error == protocol::StatusCode::OK) {
        if (!session.worker) {
          session.worker.reset(new Worker);
          session.worker->session = &session;
          session.worker->api = api_;
          needs_spawn = true;
        }
        session.worker->Publish(h.run_id, admitted_run->outbound);
        session.worker->pending_run_ids.push_back(h.run_id);
      }
      response = protocol::BuildAckFrame(h);
    }
  } else {
    if (close)
      CloseSession(conn, h.session_id, RunState::kCancelled);
    if (cancel) {
      Pump(conn);
      auto sit = conn.sessions.find(h.session_id);
      if (sit != conn.sessions.end() && sit->second->worker) {
        auto& session = *sit->second;
        auto rit = session.runs.find(h.run_id);
        if (rit != session.runs.end() && session.worker->engine_busy_run_id != h.run_id) {
          rit->second->TryTerminal(RunState::kCancelled);
        } else if (rit != session.runs.end() && rit->second->state != RunState::kCancelRequested) {
          rit->second->state = RunState::kCancelRequested;
          RequestCancel(session, h.run_id);
        }
      }
    }
    response = protocol::BuildAckFrame(h);
  }
  conn.request_cache.Record(identity, payload, payload_size, response);
  if (!conn.Enqueue(std::move(response)))
    return false;
  if (ready) {
    if (!conn.Enqueue(protocol::BuildSessionReadyFrame(ReplyHeader(conn, h.session_id))))
      return false;
    std::lock_guard<std::mutex> lock(conn.mutex);
    auto &session = *conn.sessions.at(h.session_id);
    std::lock_guard<std::mutex> session_lock(session.mutex);
    session.state = SessionState::kLogicalReady;
  }
  if (admitted_run) {
    if (admitted_run->error != protocol::StatusCode::OK)
      admitted_run->TryTerminal(RunState::kFailed);
    else if (needs_spawn && !Spawn(*admitted_session)) {
      admitted_run->error = protocol::StatusCode::ERROR_INTERNAL;
      admitted_run->TryTerminal(RunState::kFailed);
      CloseSession(conn, h.session_id, RunState::kWorkerExited);
    } else if (::WaitForSingleObject(conn.stop, 0) == WAIT_OBJECT_0) {
      CloseSession(conn, h.session_id, RunState::kBrokerLost);
    } else {
      Pump(conn);
      auto it = conn.sessions.find(h.session_id);
      if (it != conn.sessions.end())
        Dispatch(*it->second);
    }
  }
  if (api_)
    for (auto &[id, session] : conn.sessions)
      session->retired_runs.clear();
  Reclaim(conn, false);
  return true;
}
void Worker::Publish(uint32_t id, std::shared_ptr<RelayLedger> ledger) {
  if (ledger) {
    ledger->run_id = id;
    ledger_pins.push_back(ledger);
  }
  for (auto &slot : published) {
    auto *current = slot.load();
    if ((current && current->run_id == id) || (ledger && !current)) {
      slot.store(ledger.get());
      break;
    }
  }
  // Park tests after the slot update, inside publication/withdrawal work.
#if defined(V8HOST_ROUTER_TESTING)
  if (ledger_publication) ledger_publication();
#endif
  // Sequentially consistent withdrawal/hazard/recheck prevents reclaim while
  // the reader acquires shared ownership. It never retries or waits.
  auto *borrowed = ledger_reader.load();
  std::erase_if(ledger_pins, [&](const auto &pin) {
    if (pin.get() == borrowed) return false;
    for (const auto &slot : published) if (slot.load() == pin.get()) return false;
    return true;
  });
}
void Worker::DiscardMailbox() {
  mailbox_failed = true;
  while (intake_active.load()) ::SwitchToThread();
  const size_t tail = mailbox_tail.load(std::memory_order_acquire);
  for (size_t head = mailbox_head.load(); head != tail; ++head)
    mailbox[head % mailbox.size()].credit.Reset();
  mailbox_head = tail; byte_head = byte_tail.load();
}
void SBOX_CALL Worker::OnMessage(void *context, sbox_msg_kind kind, const void *data, size_t size) {
  auto &worker = *static_cast<Worker *>(context);
  auto &conn = *worker.session->conn;
  // One core reader produces; ordinary strand bookkeeping never excludes it.
#if defined(V8HOST_ROUTER_TESTING)
  if (worker.intake_entered) worker.intake_entered();
#endif
  worker.intake_active.store(true);
  if (worker.session->worker.get() != &worker || worker.mailbox_failed.load()) {
    if (auto *owner = worker.session->worker.get()) owner->mailbox_failed = true;
    worker.intake_active.store(false);
    ::SetEvent(conn.worker_wake);
    return;
  }
  const size_t tail = worker.mailbox_tail.load(std::memory_order_relaxed);
  const size_t byte_tail = worker.byte_tail.load(std::memory_order_relaxed);
  bool valid = size <= protocol::kMaxFramePayload && (!size || data) &&
      tail - worker.mailbox_head.load(std::memory_order_acquire) < worker.mailbox.size() &&
      size <= worker.mailbox_bytes.size() - (byte_tail - worker.byte_head.load(std::memory_order_acquire));
  OutputCredit credit;
  if (valid) {
    const auto *bytes = static_cast<const uint8_t *>(data);
    std::shared_ptr<RelayLedger> ledger;
    size_t charged = size + protocol::kFrameHeaderSize;
    bool late = false;
    if (kind == sbox_msg_binary && size >= v8host::kRunEnvelopeHeaderSize + 4 && v8host::IsRunEnvelope(bytes, size) &&
        bytes[4] == static_cast<uint8_t>(v8host::RunEnvelopeType::kRelay) && !bytes[5] && !bytes[6] && !bytes[7] &&
        (bytes[12] == sbox_msg_string || bytes[12] == sbox_msg_binary) && !bytes[13] && !bytes[14] && !bytes[15]) {
      const uint32_t id = bytes[8] | (uint32_t(bytes[9]) << 8) | (uint32_t(bytes[10]) << 16) | (uint32_t(bytes[11]) << 24);
      for (const auto &slot : worker.published) {
        auto *candidate = slot.load();
        worker.ledger_reader.store(candidate);
        if (candidate && slot.load() == candidate) {
#if defined(V8HOST_ROUTER_TESTING)
          if (worker.ledger_acquired) worker.ledger_acquired();
#endif
          if (candidate->run_id == id) ledger = candidate->shared_from_this();
        }
        worker.ledger_reader.store(nullptr);
        if (ledger) break;
      }
      late = !ledger;
      charged = size + protocol::kFrameHeaderSize - v8host::kRunEnvelopeHeaderSize;
    }
    if (late) {
      // Unknown envelopes still reach validation; only admitted retired ids drop.
      const uint32_t id = bytes[8] | (uint32_t(bytes[9]) << 8) | (uint32_t(bytes[10]) << 16) | (uint32_t(bytes[11]) << 24);
      if (id && id <= worker.session->highest_run_id) {
        worker.intake_active.store(false);
        return;
      }
    }
    if (kind == sbox_msg_lifecycle && size == 4) charged = protocol::kFrameHeaderSize;
    credit = conn.ChargeOutput(charged, std::move(ledger));
    // A run overflow is owned by its ledger and does not close sibling sessions.
    if (!credit.conn && ::WaitForSingleObject(conn.stop, 0) != WAIT_OBJECT_0) {
      worker.intake_active.store(false);
      ::SetEvent(conn.worker_wake);
      return;
    }
    valid = credit.conn != nullptr;
  }
  if (!valid) worker.mailbox_failed = true;
  else {
    auto &fact = worker.mailbox[tail % worker.mailbox.size()];
    fact.kind = kind; fact.size = size; fact.offset = byte_tail;
    fact.credit = std::move(credit);
    const size_t offset = byte_tail % worker.mailbox_bytes.size();
    const size_t first = (std::min)(size, worker.mailbox_bytes.size() - offset);
    if (first) std::memcpy(worker.mailbox_bytes.data() + offset, data, first);
    if (size > first) std::memcpy(worker.mailbox_bytes.data(), static_cast<const uint8_t *>(data) + first, size - first);
    worker.byte_tail.store(byte_tail + size, std::memory_order_release);
    worker.mailbox_tail.store(tail + 1, std::memory_order_release);
  }
  worker.intake_active.store(false);
  ::SetEvent(conn.worker_wake);
}
DWORD WINAPI Worker::Reap(void *context) {
  auto &worker = *static_cast<Worker *>(context);
  int32_t exit_code = 0;
  worker.api->close(worker.handle);
  worker.api->wait(worker.handle, &exit_code);
  worker.handle = nullptr;
  worker.state = WorkerState::kReaped;
  ::SetEvent(worker.session->conn->worker_wake);
  return 0;
}
bool Router::Spawn(Session &session) {
  auto &worker = *session.worker;
  session.state = SessionState::kStartingWorker;
  worker.state = WorkerState::kSpawning;
  DWORD error = 0;
  int count = ::MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      session.profile.engine_dll.data(),
      static_cast<int>(session.profile.engine_dll.size()),
      nullptr,
      0);
  if (!count)
    return false;
  std::wstring engine(count, L'\0');
  ::MultiByteToWideChar(
      CP_UTF8,
      MB_ERR_INVALID_CHARS,
      session.profile.engine_dll.data(),
      static_cast<int>(session.profile.engine_dll.size()),
      engine.data(),
      count);
  std::vector<uint8_t> config;
  if (!OpenImmutableFile(payload_directory_ + L"\\" + engine, &worker.engine_image, &error) ||
      worker.engine_image.machine() != machine_ || !TrustAllowed(VerifyTrust(worker.engine_image)) ||
      !PrepareSpawnConfig(session.config, session.profile, &config))
    return false;
  sbox_broker_worker handle = nullptr;
  if (api_->configure_and_spawn(broker_, config.data(), config.size(), &Worker::OnMessage, &worker, &handle) !=
          sbox_ok ||
      !handle)
    return false;
  worker.handle = handle;
  worker.state = WorkerState::kWarming;
  return true;
}
std::chrono::steady_clock::time_point Router::Now() const {
#if defined(V8HOST_ROUTER_TESTING)
  if (test_now)
    return test_now();
#endif
  return std::chrono::steady_clock::now();
}
DWORD Router::WakeDelay(const Connection &conn, DWORD maximum) const {
  const auto now = Now();
  for (const auto &[id, session] : conn.sessions) {
    if (!session->worker) continue;
    for (auto deadline : {session->worker->cancel_deadline, session->worker->retry_deadline}) {
      if (deadline == std::chrono::steady_clock::time_point{}) continue;
      const auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
      maximum = (std::min)(maximum, milliseconds <= 0 ? DWORD(0) : static_cast<DWORD>(milliseconds));
    }
  }
  return maximum;
}
void Router::RequestCancel(Session &session, uint32_t id) {
  auto &worker = *session.worker;
  if (worker.cancel_deadline != std::chrono::steady_clock::time_point{}) return;
  worker.cancel_deadline = Now() + kCancelFallbackTimeout;
  worker.pending_cancel_id = id;
  auto run = session.runs.find(id);
  if (run != session.runs.end()) {
    session.conn->in_relay_bytes -= run->second->queued_relay_bytes;
    run->second->queued_relay_bytes = 0; run->second->held_relays.clear();
  }
  // Cancellation retires unsent relays before replacing their retry head.
  worker.retry_deadline = {}; worker.retry_attempts = 0; worker.retry_run_id = 0;
  Dispatch(session);
}
PostOutcome Router::Post(Session &session, const std::vector<uint8_t> &bytes) {
  auto &worker = *session.worker;
  if (bytes.size() > protocol::kMaxFramePayload || !worker.handle || worker.close_called ||
      ::WaitForSingleObject(session.conn->stop, 0) == WAIT_OBJECT_0) return PostOutcome::kAmbiguous;
#if defined(V8HOST_ROUTER_TESTING)
  if (test_post) return test_post(bytes);
#endif
  const auto status = api_->post_message(worker.handle, sbox_msg_binary, bytes.data(), bytes.size());
  // The generic host adapter maps core not-written failures to sbox_error;
  // this requires a validated size and an unreaped handle.
  return status == sbox_ok ? PostOutcome::kWritten
      : status == sbox_error ? PostOutcome::kNotWritten : PostOutcome::kAmbiguous;
}
bool Router::Send(Session &session, const std::vector<uint8_t> &bytes, uint32_t id, v8host::RunEnvelopeType type) {
  auto &worker = *session.worker;
  const bool retry = worker.retry_deadline != std::chrono::steady_clock::time_point{};
  if (retry && Now() < worker.retry_deadline) return false;
  const auto outcome = Post(session, bytes);
  if (outcome == PostOutcome::kWritten) {
    worker.retry_deadline = {}; worker.retry_attempts = 0; worker.retry_run_id = 0;
    return true;
  }
  if (retry) ++worker.retry_attempts;
  if (outcome == PostOutcome::kAmbiguous || worker.retry_attempts == kPostRetryAttempts) {
    CloseSession(*session.conn, session.session_id, RunState::kWorkerExited);
    return false;
  }
  worker.retry_run_id = id; worker.retry_type = type;
  const auto delay = (std::min)(kPostRetryCap, kPostRetryInitial * (1u << (std::min)(worker.retry_attempts, 4u)));
  worker.retry_deadline = Now() + delay;
  return false;
}
void Router::Dispatch(Session &session) {
  auto &worker = *session.worker;
  if (!worker.security || worker.close_called || !worker.handle) return;
  if (worker.pending_cancel_id) {
    v8host::RunEnvelope env;
    env.type = v8host::RunEnvelopeType::kCancel; env.run_id = worker.pending_cancel_id;
    if (!Send(session, v8host::EncodeRunEnvelope(env), env.run_id, env.type)) return;
    worker.pending_cancel_id = 0;
  }
  if (!worker.engine_busy_run_id && !worker.pending_run_ids.empty()) {
    const uint32_t id = worker.pending_run_ids.front();
    auto it = session.runs.find(id);
    if (it == session.runs.end()) { worker.pending_run_ids.pop_front(); return; }
    v8host::RunEnvelope env;
    env.run_id = id; env.payload = it->second->guest;
    if (!Send(session, v8host::EncodeRunEnvelope(env), id, env.type)) return;
    worker.pending_run_ids.pop_front();
    worker.engine_busy_run_id = worker.active_run_id = id;
    it->second->guest.clear();
    it->second->state = RunState::kActive;
  }
  auto it = session.runs.find(worker.engine_busy_run_id);
  if (it == session.runs.end()) return;
  auto &run = *it->second;
  for (size_t posted = 0; posted < 256 && !run.held_relays.empty(); ++posted) {
    if (!Send(session, run.held_relays.front(), run.run_id, v8host::RunEnvelopeType::kRelay)) return;
    session.conn->in_relay_bytes -= run.held_relays.front().size();
    run.queued_relay_bytes -= static_cast<uint32_t>(run.held_relays.front().size());
    run.held_relays.pop_front();
  }
}
void Router::CloseSession(Connection &conn, uint32_t id, RunState terminal) {
  std::lock_guard<std::mutex> lock(conn.mutex);
  auto it = conn.sessions.find(id);
  if (it == conn.sessions.end())
    return;
  Session *session = it->second.get();
  bool has_worker = session->worker != nullptr;
  if (has_worker) session->worker->DiscardMailbox();
  RetireSessionLocked(conn, id, terminal);
  if (terminal == RunState::kWorkerExited)
    conn.Enqueue(protocol::BuildWorkerExitFrame(ReplyHeader(conn, id)));
  if (!has_worker)
    return;
  auto &worker = *session->worker;
  worker.cancel_deadline = {}; worker.retry_deadline = {};
  worker.retry_attempts = 0; worker.retry_run_id = 0; worker.pending_cancel_id = 0;
  worker.engine_busy_run_id = 0;
  if (worker.handle && !worker.close_called) {
    worker.close_called = true;
    worker.state = WorkerState::kCloseRequested;
    worker.wait_called = true;
    worker.cleanup = ::CreateThread(nullptr, 0, &Worker::Reap, &worker, 0, nullptr);
    if (!worker.cleanup)
      conn.Stop();
  }
}
void Router::Reclaim(Connection &conn, bool join) {
  for (auto it = conn.retired_sessions.begin(); it != conn.retired_sessions.end();) {
    auto &session = **it;
    auto *worker = session.worker.get();
    if (join && worker && worker->wait_called && !worker->cleanup && worker->handle)
      Worker::Reap(worker);
    if (worker && worker->cleanup && ::WaitForSingleObject(worker->cleanup, join ? INFINITE : 0) == WAIT_OBJECT_0) {
      ::CloseHandle(worker->cleanup);
      worker->cleanup = nullptr;
      it = conn.retired_sessions.erase(it);
    } else if (api_ && (!worker || (!worker->cleanup && !worker->handle))) {
      // Failed spawn returns only after any unpublished callback reader has joined.
      it = conn.retired_sessions.erase(it);
    } else {
      ++it;
    }
  }
}
void Router::Pump(Connection &conn) {
  std::vector<uint32_t> ids;
  for (auto &[id, session] : conn.sessions)
    if (session->worker)
      ids.push_back(id);
  for (uint32_t id : ids) {
    auto it = conn.sessions.find(id);
    if (it == conn.sessions.end())
      continue;
    auto &session = *it->second;
    auto &worker = *session.worker;
    if (!worker.handle)
      continue;
    if (worker.mailbox_failed.load()) {
      CloseSession(conn, id, RunState::kWorkerExited);
      continue;
    }
    std::vector<uint32_t> overflowed;
    for (const auto &[run_id, run] : session.runs)
      if (run->outbound->failed) overflowed.push_back(run_id);
    for (uint32_t run_id : overflowed) {
      if (!conn.sessions.contains(id)) break;
      auto &run = *session.runs.at(run_id);
      run.error = protocol::StatusCode::ERROR_QUOTA;
      run.TryTerminal(RunState::kFailed);
      if (worker.engine_busy_run_id == run_id) RequestCancel(session, run_id);
    }
    if (!conn.sessions.contains(id)) continue;
    Worker::Fact fact;
    std::array<uint8_t, protocol::kMaxFramePayload> data;
    for (size_t drained = 0; drained < worker.mailbox.size(); ++drained) {
      const size_t head = worker.mailbox_head.load(std::memory_order_relaxed);
      const size_t tail = worker.mailbox_tail.load(std::memory_order_acquire);
      if (worker.mailbox_failed.load(std::memory_order_acquire) || head == tail)
        break;
      auto &slot = worker.mailbox[head % worker.mailbox.size()];
      fact.kind = slot.kind;
      fact.size = slot.size;
      fact.offset = slot.offset;
      fact.credit = std::move(slot.credit);
      const size_t offset = slot.offset % worker.mailbox_bytes.size();
      const size_t first = (std::min)(slot.size, worker.mailbox_bytes.size() - offset);
      std::memcpy(data.data(), worker.mailbox_bytes.data() + offset, first);
      if (slot.size > first) std::memcpy(data.data() + first, worker.mailbox_bytes.data(), slot.size - first);
#if defined(V8HOST_ROUTER_TESTING)
      if (worker.mailbox_readout)
        worker.mailbox_readout();
#endif
      worker.byte_head.store(fact.offset + fact.size, std::memory_order_release);
      worker.mailbox_head.store(head + 1, std::memory_order_release);
      if (worker.mailbox_failed.load(std::memory_order_acquire))
        break;
      bool valid = true;
      if (!fact.credit.relay) fact.credit.Reset();
      if (fact.kind == sbox_msg_lifecycle) {
        uint32_t phase = 0;
        if (fact.size == 4)
          phase = data[0] | (uint32_t(data[1]) << 8) | (uint32_t(data[2]) << 16) |
              (uint32_t(data[3]) << 24);
        if (phase == SBOX_LIFECYCLE_STARTUP) {
          if (!worker.startup) {
            worker.startup = true;
            worker.engine_image = HeldFile();
            session.state = SessionState::kStartupReady;
            conn.Enqueue(protocol::BuildStartupReadyFrame(ReplyHeader(conn, id)));
          }
        } else if (phase == SBOX_LIFECYCLE_SECURITY && worker.startup) {
          if (!worker.security) {
            worker.security = true;
            session.state = SessionState::kOpen;
            worker.state = WorkerState::kRunning;
            conn.Enqueue(protocol::BuildSecurityReadyFrame(ReplyHeader(conn, id)));
          }
        } else if (phase == SBOX_LIFECYCLE_EXIT) {
          CloseSession(conn, id, RunState::kWorkerExited);
          break;
        } else {
          valid = false;
        }
      } else {
        v8host::RunEnvelope env;
        valid = fact.kind == sbox_msg_binary && v8host::DecodeRunEnvelope(data.data(), fact.size, &env) &&
            worker.security && env.run_id != 0 &&
            (env.type == v8host::RunEnvelopeType::kRelay || env.type == v8host::RunEnvelopeType::kResult ||
             env.type == v8host::RunEnvelopeType::kRunError) &&
            (env.type != v8host::RunEnvelopeType::kRelay || env.relay_kind == sbox_msg_string ||
             env.relay_kind == sbox_msg_binary);
        if (valid && env.run_id != worker.engine_busy_run_id && env.run_id <= session.highest_run_id)
          continue;
        valid = valid && env.run_id == worker.engine_busy_run_id;
        if (valid) {
          auto rit = session.runs.find(env.run_id);
          if (rit != session.runs.end() && rit->second->outbound->failed.load()) {
            rit->second->error = protocol::StatusCode::ERROR_QUOTA;
            rit->second->TryTerminal(RunState::kFailed);
            if (env.type == v8host::RunEnvelopeType::kRelay) RequestCancel(session, env.run_id);
            rit = session.runs.end();
          }
          if (env.type == v8host::RunEnvelopeType::kRelay) {
            valid = env.relay_kind == sbox_msg_string || env.relay_kind == sbox_msg_binary;
            if (valid && rit != session.runs.end()) {
              auto header = ReplyHeader(conn, id, env.run_id);
              header.type = protocol::MessageType::RELAY_FROM_WORKER;
              auto frame = protocol::BuildRelayFrame(header, env.relay_kind, env.payload.data(), env.payload.size());
              auto credit = std::move(fact.credit);
              if (!credit.conn) credit = conn.ChargeOutput(frame.size(), rit->second->outbound);
              if (credit.conn) conn.Enqueue(std::move(frame), std::move(credit));
              else if (rit->second->outbound->failed) {
                rit->second->error = protocol::StatusCode::ERROR_QUOTA;
                rit->second->TryTerminal(RunState::kFailed);
                RequestCancel(session, env.run_id);
              }
            }
          } else if (env.type == v8host::RunEnvelopeType::kResult || env.type == v8host::RunEnvelopeType::kRunError) {
            worker.cancel_deadline = {}; worker.retry_deadline = {};
            worker.retry_attempts = 0; worker.retry_run_id = 0; worker.pending_cancel_id = 0;
            worker.engine_busy_run_id = 0;
            if (rit != session.runs.end()) {
              if (env.type == v8host::RunEnvelopeType::kRunError) {
                rit->second->error = protocol::StatusCode::ERROR_INTERNAL;
                rit->second->TryTerminal(RunState::kFailed);
              } else {
                rit->second->TryTerminal(
                    env.disposition == v8host::RunEnvelopeDisposition::kCompleted ? RunState::kCompleted
                                                                                  : RunState::kCancelled);
              }
            }
          } else {
            valid = false;
          }
        }
      }
      if (!valid) {
        CloseSession(conn, id, RunState::kWorkerExited);
        break;
      }
    }
    if (conn.sessions.contains(id) && worker.mailbox_failed.load(std::memory_order_acquire))
      CloseSession(conn, id, RunState::kWorkerExited);
    if (conn.sessions.contains(id) && worker.cancel_deadline != std::chrono::steady_clock::time_point{} &&
        Now() >= worker.cancel_deadline) {
      CloseSession(conn, id, RunState::kWorkerExited);
    }
    if (conn.sessions.contains(id)) {
      if (worker.mailbox_head.load(std::memory_order_relaxed) != worker.mailbox_tail.load(std::memory_order_acquire))
        ::SetEvent(conn.worker_wake);
      Dispatch(session);
      // Only the strand borrows production run storage.
      session.retired_runs.clear();
    }
  }
  Reclaim(conn, false);
#if defined(V8HOST_ROUTER_TESTING)
  if (test_pump_complete)
    test_pump_complete();
#endif
}
void Router::Close(Connection &conn) {
  conn.Stop();
  conn.state = ConnState::kClosing;
  while (!conn.sessions.empty())
    CloseSession(conn, conn.sessions.begin()->first, RunState::kBrokerLost);
  Reclaim(conn, true);
  conn.dispatcher = nullptr;
  conn.state = ConnState::kClosed;
}
} // namespace v8host::coordinator
