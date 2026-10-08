// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "v8host_router.h"
#include <algorithm>
#include <chrono>

namespace v8host::coordinator {
Connection::Connection() {
  out_wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
  stop = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
}
Connection::~Connection() {
  Stop();
  JoinWriter();
  if (out_wake)
    ::CloseHandle(out_wake);
  if (stop)
    ::CloseHandle(stop);
}
void Connection::Stop() {
  if (stop)
    ::SetEvent(stop);
  if (out_wake)
    ::SetEvent(out_wake);
}
bool Connection::Enqueue(std::vector<uint8_t> frame) {
  std::lock_guard<std::mutex> lock(out_mutex);
  if (!out_wake || !stop || ::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0)
    return false;
  if (out_control_requests >= protocol::kMaxControlQueueRequests ||
      frame.size() > protocol::kMaxControlQueueBytes - out_control_bytes) {
    Stop();
    return false;
  }
  out_control_bytes += static_cast<uint32_t>(frame.size());
  ++out_control_requests;
  out_queue.push_back(std::move(frame));
  ::SetEvent(out_wake);
  return true;
}
bool Connection::TakeOutput(std::vector<uint8_t> *frame) {
  std::lock_guard<std::mutex> lock(out_mutex);
  if (out_queue.empty())
    return false;
  *frame = std::move(out_queue.front());
  out_queue.pop_front();
  return true;
}
void Connection::CompleteOutput(size_t bytes) {
  std::lock_guard<std::mutex> lock(out_mutex);
  out_control_bytes -= static_cast<uint32_t>(bytes);
  --out_control_requests;
  out_drained_.notify_all();
}
bool Connection::DrainOutput(DWORD timeout_ms) {
  std::unique_lock<std::mutex> lock(out_mutex);
  return out_drained_.wait_for(
      lock, std::chrono::milliseconds(timeout_ms), [&] { return out_control_requests == 0; });
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
    ok = ::GetOverlappedResult(conn.pipe, &ov, transferred, FALSE) != FALSE;
  } else if (pending) {
#if defined(V8HOST_ROUTER_TESTING)
    HANDLE barrier = write ? conn.write_pending : conn.read_pending;
    if (barrier)
      ::SetEvent(barrier);
#endif
    HANDLE waits[] = {conn.stop, ov.hEvent};
    if (::WaitForMultipleObjects(2, waits, FALSE, timeout_ms) == WAIT_OBJECT_0 + 1) {
      ok = ::GetOverlappedResult(conn.pipe, &ov, transferred, FALSE) != FALSE;
      pending = false;
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
bool Connection::ReadFrame(uint8_t *buffer, DWORD capacity, DWORD *size, DWORD timeout_ms) {
  if (!stop || ::WaitForSingleObject(stop, 0) == WAIT_OBJECT_0)
    return false;
  return Transfer(*this, false, buffer, capacity, size, timeout_ms);
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
    if (session->worker) {
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
      protocol::ErrorPayload error;
      error.status_code = protocol::StatusCode::ERROR_INTERNAL;
      auto frame = protocol::BuildErrorFrame(header, error);
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
    for (auto &[run_id, run] : session->runs)
      runs.push_back(run.get());
  }
  for (Run *run : runs)
    run->TryTerminal(terminal);
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    session->state = SessionState::kClosed;
  }
  conn.retired_sessions.push_back(std::move(session));
}
} // namespace

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
  if (!h.session_id || h.session_id == UINT32_MAX || h.run_id == UINT32_MAX || h.request_id == UINT32_MAX)
    return false;
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
    return protocol::DecodeRelayPayload(payload, payload_size, &kind, &body, &body_size) &&
        (kind == sbox_msg_string || kind == sbox_msg_binary);
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
  if (create) {
    SessionConfig config;
    if (!protocol::DecodeCreateSessionPayload(payload, payload_size, &config))
      return false;
    std::lock_guard<std::mutex> lock(conn.mutex);
    if (conn.sessions.contains(h.session_id))
      return false;
    if (!ValidateSessionConfig(config, mode_) || h.session_id <= conn.highest_session_id) {
      response = Error(h, protocol::StatusCode::ERROR_BAD_STATE);
    } else if (conn.sessions.size() >= protocol::kMaxSessionsPerConnection) {
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
    response = Error(h, protocol::StatusCode::ERROR_BAD_STATE);
  } else {
    if (close) {
      std::lock_guard<std::mutex> lock(conn.mutex);
      RetireSessionLocked(conn, h.session_id, RunState::kCancelled);
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
    conn.sessions.at(h.session_id)->state = SessionState::kLogicalReady;
  }
  return true;
}
void Router::Close(Connection &conn) {
  conn.Stop();
  std::lock_guard<std::mutex> lock(conn.mutex);
  conn.state = ConnState::kClosing;
  while (!conn.sessions.empty())
    RetireSessionLocked(conn, conn.sessions.begin()->first, RunState::kBrokerLost);
  conn.state = ConnState::kClosed;
}
} // namespace v8host::coordinator
