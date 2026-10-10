#include "v8host_test_support.h"

#include "v8host_broker_rendezvous.h"
#include "v8host_client.h"
#include "v8host_broker.h"
#include "v8host_file_identity.h"
#include "v8host_payload_identity.h"
#include "v8host_peer_auth.h"
#include "v8host_router.h"
#include "../v8host_engine.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

bool V8HostEngineTestBatch(const std::vector<v8host::RunEnvelope> &, bool, size_t *, size_t *, size_t *);

namespace {

using v8host::BrokerConnection;
using v8host::BrokerMode;
using v8host::BrokerRendezvous;
using v8host::HelloResult;
using v8host::RendezvousStatus;
using v8host::test::ExecutableDirectory;

bool ConnectAndHandshake(BrokerMode mode,
                         uint32_t request_id,
                         BrokerConnection* connection,
                         HelloResult* result,
                         std::string* detail) {
  BrokerRendezvous rendezvous(ExecutableDirectory(), mode);
  const RendezvousStatus connected = rendezvous.ConnectOrLaunch(connection);
  if (connected != RendezvousStatus::kOk) {
    *detail = "connect status=" + std::to_string(static_cast<int>(connected));
    return false;
  }
  const RendezvousStatus handshook = connection->Handshake(request_id, result);
  // Reciprocal peer auth plus a successful HELLO_ACK already prove the broker
  // authenticated this client, so no observed-client-pid echo is checked here;
  // client-identity rejection is covered by the dedicated peer-auth suite.
  if (handshook != RendezvousStatus::kOk) {
    *detail = "handshake status=" + std::to_string(static_cast<int>(handshook));
    return false;
  }
  // End-to-end check of the negotiated endpoint mode: the broker advertises its
  // own mode in HELLO_ACK, which must match this client's requested BrokerMode
  // on the wire (Dedicated=0 / Shared=1 on both surfaces). This is the only
  // place the coordinator's mode->endpoint_mode mapping is proven end-to-end.
  if (result->endpoint_mode != static_cast<uint32_t>(mode)) {
    *detail = "endpoint_mode=" + std::to_string(result->endpoint_mode) +
              " expected=" + std::to_string(static_cast<uint32_t>(mode));
    return false;
  }
  return true;
}

bool TerminalOrderings(std::string *detail) {
  namespace router = v8host::coordinator;
  for (bool cancel_first : {false, true}) {
    router::Connection conn;
    router::Session session;
    session.conn = &conn;
    session.session_id = 1;
    session.worker = std::make_unique<router::Worker>();
    session.worker->active_run_id = 1;
    session.worker->pending_run_ids = {1, 2};
    auto run = std::make_unique<router::Run>();
    run->session = &session;
    run->run_id = 1;
    router::Run *contender = run.get();
    session.runs.emplace(1, std::move(run));
    bool removed_before_emit = false;
    session.terminal_removed = [&] { removed_before_emit = session.runs.empty() && conn.out_queue.empty(); };
    const auto first = cancel_first ? router::RunState::kCancelled : router::RunState::kCompleted;
    const auto second = cancel_first ? router::RunState::kCompleted : router::RunState::kCancelled;
    if (contender->TryTerminal(router::RunState::kActive) || !contender->TryTerminal(first) ||
        contender->TryTerminal(second) || !removed_before_emit || session.retired_runs.size() != 1 ||
        conn.out_queue.size() != 1 || contender->state != first || session.worker->active_run_id != 0 ||
        session.worker->pending_run_ids != std::deque<uint32_t>{2}) {
      *detail = "terminal winner/removal/retention invariant";
      return false;
    }
  }
  return true;
}

namespace router = v8host::coordinator;
namespace protocol = v8host::protocol;
protocol::FrameHeader ControlHeader(uint32_t request, uint32_t session = 1, uint32_t run = 0) {
  protocol::FrameHeader h;
  h.version_major = protocol::kWireVersionMajor;
  h.version_minor = protocol::kWireVersionMinor;
  h.conn_id = 1;
  h.session_id = session;
  h.run_id = run;
  h.request_id = request;
  return h;
}
protocol::CreateSessionPayload LogicalConfig() {
  protocol::CreateSessionPayload config;
  config.prohibit_dynamic_code = true;
  return config;
}
void OpenLocal(router::Connection &conn) {
  conn.conn_id = 1;
  conn.state = router::ConnState::kOpen;
}
bool LocalRoute(router::Router &service, router::Connection &conn, const std::vector<uint8_t> &frame) {
  return service.Route(conn, frame.data(), frame.size());
}
bool PopFrame(router::Connection &conn, protocol::FrameHeader *h, protocol::StatusCode *error = nullptr) {
  std::vector<uint8_t> bytes;
  if (!conn.TakeOutput(&bytes))
    return false;
  conn.CompleteOutput(bytes.size());
  const uint8_t *payload;
  size_t size;
  if (protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), h, &payload, &size) != protocol::DecodeStatus::kOk)
    return false;
  if (error) {
    protocol::ErrorPayload decoded;
    if (!protocol::DecodeErrorPayload(payload, size, &decoded))
      return false;
    *error = decoded.status_code;
  }
  return true;
}
void DrainLocal(router::Connection &conn) {
  protocol::FrameHeader h;
  while (PopFrame(conn, &h)) {
  }
}
bool ConfigFidelity(size_t count, std::string *detail) {
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  auto config = LogicalConfig();
  config.integrity = sbox_integrity_untrusted;
  config.delayed_integrity = sbox_integrity_low;
  config.initial_token = sbox_token_restricted_same_access;
  config.lockdown_token = sbox_token_limited;
  config.use_app_container = true;
  config.low_privilege_app_container = true;
  config.app_container_profile = "owned-profile";
  for (size_t i = 0; i < count; ++i) {
    config.file_rules.push_back({i % 2 == 0, "C:\\data\\rule" + std::to_string(i)});
    config.capabilities.push_back("cap-" + std::to_string(i));
  }
  auto frame = protocol::BuildCreateSessionFrame(ControlHeader(1), config);
  if (!LocalRoute(service, conn, frame))
    return false;
  config.app_container_profile = "mutated";
  config.file_rules.clear();
  config.capabilities.clear();
  frame.assign(frame.size(), 0);
  const auto &owned = conn.sessions.at(1)->config;
  protocol::StartRunPayload inputs;
  inputs.tier_override = -1;
  router::BoundProfile profile;
  std::vector<uint8_t> bytes;
  v8host::V8HostSpawnConfigV1 spawn;
  if (!router::PrepareProfile(owned, inputs, L"C:\\payload", &profile) ||
      !router::PrepareSpawnConfig(owned, profile, &bytes) ||
      !v8host::V8HostSpawnConfigV1::Decode(bytes.data(), bytes.size(), &spawn) || spawn.tier != owned.tier ||
      spawn.integrity != owned.integrity || spawn.delayed_integrity != owned.delayed_integrity ||
      spawn.initial_token != owned.initial_token || spawn.lockdown_token != owned.lockdown_token ||
      spawn.prohibit_dynamic_code != owned.prohibit_dynamic_code ||
      spawn.use_app_container != owned.use_app_container ||
      spawn.low_privilege_app_container != owned.low_privilege_app_container ||
      spawn.app_container_profile != "owned-profile" || spawn.file_rules.size() != count ||
      spawn.capabilities != owned.capabilities || spawn.effective_tier != profile.effective_tier ||
      spawn.engine_dll != profile.engine_dll || spawn.snapshot_path != profile.snapshot_path) {
    *detail = "owned config/spawn fidelity";
    return false;
  }
  for (size_t i = 0; i < count; ++i)
    if (spawn.file_rules[i].readonly != owned.file_rules[i].readonly ||
        spawn.file_rules[i].pattern != owned.file_rules[i].pattern)
      return false;
  return !conn.sessions.at(1)->worker && !conn.sessions.at(1)->profile_bound;
}
bool ConfigFidelity0(std::string *detail) {
  return ConfigFidelity(0, detail);
}
bool ConfigFidelity64(std::string *detail) {
  return ConfigFidelity(64, detail);
}
bool ProfileValidation(std::string *detail) {
  auto config = LogicalConfig();
  for (auto field :
       {&protocol::CreateSessionPayload::broker_mode,
        &protocol::CreateSessionPayload::tier,
        &protocol::CreateSessionPayload::integrity,
        &protocol::CreateSessionPayload::delayed_integrity,
        &protocol::CreateSessionPayload::initial_token,
        &protocol::CreateSessionPayload::lockdown_token}) {
    for (int bad : {-1, 99}) {
      auto invalid = config;
      invalid.*field = bad;
      if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
        return false;
    }
  }
  auto invalid = config;
  invalid.broker_mode = 1;
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.low_privilege_app_container = true;
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.capabilities = {"cap"};
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.use_app_container = true;
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.tier = 1;
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.prohibit_dynamic_code = false;
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.file_rules.resize(65);
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.use_app_container = true;
  invalid.app_container_profile = "profile";
  invalid.capabilities.resize(65);
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  invalid = config;
  invalid.file_rules = {{true, std::string("bad\0path", 8)}};
  if (router::ValidateSessionConfig(invalid, BrokerMode::kDedicated))
    return false;
  protocol::StartRunPayload inputs;
  inputs.tier_override = -1;
  router::BoundProfile profile;
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile) || profile.effective_tier != 0 ||
      profile.engine_dll != "v8jsisb.dll")
    return false;
  for (int bad : {-2, 1, 2}) {
    inputs.tier_override = bad;
    if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
      return false;
  }
  config.tier = 1;
  config.prohibit_dynamic_code = false;
  inputs.tier_override = -1;
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile) || profile.engine_dll != "v8jsi.dll")
    return false;
  inputs.tier_override = 0;
  if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  inputs.tier_override = -1;
  inputs.has_engine_override = true;
  for (const std::string &bad : {"", ".", "x..dll", "C:x.dll", "dir/x.dll", "dir\\x.dll", "\xc0\x80"}) {
    inputs.engine_filename = bad;
    if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
      return false;
  }
  inputs.engine_filename = "custom.dll";
  inputs.has_snapshot = true;
  for (const std::string &bad :
       {"../escape.bin",
        "C:\\outside\\snap.bin",
        "\\\\server\\share\\a",
        "\\\\?\\C:\\payload\\a",
        "C:relative",
        "\\rooted",
        "a:stream",
        "a.",
        "NUL.bin",
        "\xc0\x80"}) {
    inputs.snapshot_path = bad;
    if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
      return false;
  }
  inputs.snapshot_path = "sub/../snap.bin";
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile) ||
      profile.snapshot_path != "C:\\payload\\snap.bin") {
    *detail = "snapshot canonicalization";
    return false;
  }
  inputs.snapshot_path = "C:\\PAYLOAD\\snap.bin";
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  inputs.snapshot_path.assign(5000, 'x');
  if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  inputs.snapshot_path = "snap.bin";
  inputs.schema_version = 2;
  if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  inputs.schema_version = protocol::kMessageSchemaVersion;
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;

  inputs.snapshot_path.assign(4096 - 20 - inputs.engine_filename.size() - std::string("C:\\payload\\").size(), 'x');
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile)) {
    *detail = "worker-profile exact size";
    return false;
  }
  inputs.snapshot_path.push_back('x');
  if (router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  inputs.snapshot_path = "snap.bin";
  if (!router::PrepareProfile(config, inputs, L"C:\\payload", &profile))
    return false;
  auto large_config = config;
  large_config.file_rules = {{true, std::string(32700, 'x')}, {false, std::string(32100, 'y')}};
  auto large_inputs = inputs;
  large_inputs.has_snapshot = false;
  large_inputs.snapshot_path.clear();
  large_inputs.engine_filename.assign(4000, 'e');
  router::BoundProfile large_profile;
  std::vector<uint8_t> too_large;
  if (!router::PrepareProfile(large_config, large_inputs, L"C:\\payload", &large_profile) ||
      router::PrepareSpawnConfig(large_config, large_profile, &too_large)) {
    *detail = "spawn-config encoded size ceiling";
    return false;
  }
  router::Session session;
  if (router::BindProfile(session, profile) != protocol::StatusCode::OK ||
      router::BindProfile(session, profile) != protocol::StatusCode::OK)
    return false;
  auto conflict = profile;
  conflict.engine_dll = "different.dll";
  if (router::BindProfile(session, conflict) != protocol::StatusCode::ERROR_PROFILE_ALREADY_BOUND ||
      session.profile.engine_dll != "custom.dll" || session.worker)
    return false;
  return true;
}

bool PipeIo(HANDLE pipe, bool write, std::vector<uint8_t> *bytes) {
  OVERLAPPED ov = {};
  ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ov.hEvent)
    return false;
  DWORD len = 0;
  BOOL started = write ? ::WriteFile(pipe, bytes->data(), static_cast<DWORD>(bytes->size()), nullptr, &ov)
                       : ::ReadFile(pipe, bytes->data(), static_cast<DWORD>(bytes->size()), nullptr, &ov);
  bool pending = !started && ::GetLastError() == ERROR_IO_PENDING;
  bool ok = false;
  if (started)
    ok = ::GetOverlappedResult(pipe, &ov, &len, FALSE) != FALSE;
  else if (pending && ::WaitForSingleObject(ov.hEvent, 3000) == WAIT_OBJECT_0) {
    ok = ::GetOverlappedResult(pipe, &ov, &len, FALSE) != FALSE;
    pending = false;
  }
  if (pending) {
    ::CancelIoEx(pipe, &ov);
    ::GetOverlappedResult(pipe, &ov, &len, TRUE);
  }
  ::CloseHandle(ov.hEvent);
  if (ok && !write)
    bytes->resize(len);
  return ok && (!write || len == bytes->size());
}
struct WireHarness {
  BrokerConnection connection;
  HelloResult hello;
  HANDLE process = nullptr;
  ~WireHarness() {
    connection.Close();
    if (process) {
      ::WaitForSingleObject(process, 10000);
      ::CloseHandle(process);
    }
  }
  bool Open(std::string *detail) {
    if (!ConnectAndHandshake(BrokerMode::kDedicated, 900, &connection, &hello, detail))
      return false;
    process = ::OpenProcess(SYNCHRONIZE, FALSE, connection.broker_pid());
    return process != nullptr;
  }
  protocol::FrameHeader Header(uint32_t request, uint32_t session = 1, uint32_t run = 0) {
    auto h = ControlHeader(request, session, run);
    h.conn_id = hello.conn_id;
    h.version_major = hello.selected_major;
    h.version_minor = hello.selected_minor;
    return h;
  }
  bool Send(std::vector<uint8_t> bytes) {
    return PipeIo(connection.pipe(), true, &bytes);
  }
  bool Receive(std::vector<uint8_t> *bytes, protocol::FrameHeader *h) {
    bytes->resize(protocol::kMaxFrameSize);
    const uint8_t *payload;
    size_t size;
    return PipeIo(connection.pipe(), false, bytes) &&
        protocol::DecodeAndValidateFrame(bytes->data(), bytes->size(), h, &payload, &size) ==
        protocol::DecodeStatus::kOk;
  }
  bool Expect(protocol::MessageType type, uint32_t request, uint32_t session, uint32_t run = 0) {
    std::vector<uint8_t> bytes;
    protocol::FrameHeader h;
    bool ok = Receive(&bytes, &h) && h.type == type && h.conn_id == hello.conn_id && h.request_id == request &&
        h.session_id == session && h.run_id == run;
    if (!ok)
      std::printf("wire expected type=%u request=%u run=%u; received type=%u request=%u run=%u bytes=%zu\n",
          static_cast<unsigned>(type), request, run, static_cast<unsigned>(h.type), h.request_id, h.run_id, bytes.size());
    return ok;
  }
  bool Closed() {
    std::vector<uint8_t> bytes(protocol::kMaxFrameSize);
    return !PipeIo(connection.pipe(), false, &bytes) && ::WaitForSingleObject(process, 3000) == WAIT_OBJECT_0;
  }
  bool Finish() {
    connection.Close();
    return ::WaitForSingleObject(process, 5000) == WAIT_OBJECT_0;
  }
};
struct EngineFixture {
  sbox_worker_api api = {};
  std::vector<uint8_t> profile;
  std::vector<v8host::RunEnvelope> output;
  bool invalid = false;
  EngineFixture() {
    v8host::V8HostWorkerProfileV1 config;
    config.jitless = 1;
    config.engine_dll = "v8jsisb.dll";
    profile = config.Encode();
    api.struct_size = sizeof(api);
    api.get_plugin_data = [](sbox_worker worker, const void **data, size_t *size) -> sbox_status {
      auto &f = *reinterpret_cast<EngineFixture *>(worker);
      *data = f.profile.data(); *size = f.profile.size(); return sbox_ok;
    };
    api.acg_enabled = [](sbox_worker) { return 1; };
    api.post_message = [](sbox_worker worker, sbox_msg_kind kind, const void *data, size_t size) -> sbox_status {
      auto &f = *reinterpret_cast<EngineFixture *>(worker);
      v8host::RunEnvelope env;
      if (kind != sbox_msg_binary || !v8host::DecodeRunEnvelope(static_cast<const uint8_t *>(data), size, &env)) {
        f.invalid = true;
        return sbox_error;
      }
      f.output.push_back(std::move(env));
      return sbox_ok;
    };
  }
  ~EngineFixture() { V8HostEngineShutdown(reinterpret_cast<sbox_worker>(this)); }
  bool Warm() { return V8HostEngineWarmup(reinterpret_cast<sbox_worker>(this), &api) == sbox_ok; }
  bool Batch(const std::vector<v8host::RunEnvelope> &batch, bool closing, size_t *bytes, size_t *frames) {
    size_t remaining = 99;
    return V8HostEngineTestBatch(batch, closing, bytes, frames, &remaining) && remaining == 0 && !invalid;
  }
};
v8host::RunEnvelope GuestStart(const std::string &guest, uint32_t id = 1) {
  v8host::RunEnvelope env;
  env.run_id = id;
  env.payload.assign(guest.begin(), guest.end());
  return env;
}
v8host::RunEnvelope GuestRelay(size_t size, uint32_t id = 1) {
  v8host::RunEnvelope env;
  env.type = v8host::RunEnvelopeType::kRelay;
  env.run_id = id;
  env.relay_kind = sbox_msg_binary;
  env.payload.assign(size, 7);
  return env;
}
bool StartRelaySameDrain(std::string *detail) {
  EngineFixture f;
  size_t bytes, frames;
  if (!f.Warm() || !f.Batch({GuestStart("var n=0;host.onmessage=function(m){host.postMessageBinary(m);"
          "if(++n===2)host.complete();};"), GuestRelay(2), GuestRelay(3)}, false, &bytes, &frames) ||
      frames != 2 || bytes != 37 || f.output.size() != 3 ||
      f.output[0].payload != std::vector<uint8_t>(2, 7) || f.output[1].payload != std::vector<uint8_t>(3, 7) ||
      f.output[2].type != v8host::RunEnvelopeType::kResult ||
      f.output[2].disposition != v8host::RunEnvelopeDisposition::kCompleted) {
    *detail = "forced START+RELAY FIFO in production scheduler";
    return false;
  }
  return true;
}
bool StartCancelSameDrain(std::string *detail) {
  EngineFixture f;
  size_t bytes, frames;
  v8host::RunEnvelope cancel;
  cancel.type = v8host::RunEnvelopeType::kCancel;
  cancel.run_id = 1;
  if (!f.Warm() || !f.Batch({GuestStart("host.onmessage=function(m){host.postMessageBinary(m);};"),
          cancel, GuestRelay(1)}, false, &bytes, &frames) || frames != 2 || f.output.size() != 1 ||
      f.output[0].type != v8host::RunEnvelopeType::kResult ||
      f.output[0].disposition != v8host::RunEnvelopeDisposition::kCancelled) {
    *detail = "forced START+CANCEL production branch";
    return false;
  }
  return true;
}
bool StartBridgeOverflow(std::string *detail) {
  EngineFixture f;
  if (!f.Warm())
    return false;
  size_t bytes, frames;
  for (const std::string guest : {"host.complete();", "throw new Error('bridge guest');",
                                 "host.complete();throw new Error('bridge guest');"}) {
    const bool throws = guest.find("throw") != std::string::npos;
    for (bool byte_limit : {false, true}) {
      for (bool overflow : {false, true}) {
        f.output.clear();
        std::vector<v8host::RunEnvelope> batch{GuestStart(guest)};
        if (byte_limit) {
          // 16 full envelopes and one tail hit exactly 1 MiB.
          for (int i = 0; i < 16; ++i)
            batch.push_back(GuestRelay(65512));
          batch.push_back(GuestRelay(112 + (overflow ? 1 : 0)));
        } else {
          for (size_t i = 0; i < 256 + (overflow ? 1 : 0); ++i)
            batch.push_back(GuestRelay(0));
        }
        const bool error = overflow || throws;
        if (!f.Batch(batch, false, &bytes, &frames) || f.output.size() != 1 || f.output[0].run_id != 1 ||
            f.output[0].type != (error ? v8host::RunEnvelopeType::kRunError : v8host::RunEnvelopeType::kResult) ||
            (error && f.output[0].status_code != static_cast<uint32_t>(protocol::StatusCode::ERROR_INTERNAL)) ||
            (!error && f.output[0].disposition != v8host::RunEnvelopeDisposition::kCompleted) ||
            bytes > protocol::kMaxQueuedRelayBytesPerRun || frames > 256 ||
            (!overflow && byte_limit && bytes != protocol::kMaxQueuedRelayBytesPerRun) ||
            (!byte_limit && frames != 256)) {
          *detail = "activation bridge limit/+1 with completed/thrown-guest terminal priority";
          return false;
        }
      }
    }
  }
  for (bool overflow : {false, true}) {
    f.output.clear();
    std::vector<v8host::RunEnvelope> batch;
    for (uint32_t id = 1; id <= protocol::kMaxInFlightRunsPerSession + (overflow ? 1 : 0); ++id) {
      batch.push_back(GuestStart("host.complete();", id));
      batch.push_back(GuestRelay(1, id));
    }
    size_t remaining = 99;
    const bool ok = V8HostEngineTestBatch(batch, false, &bytes, &frames, &remaining);
    if (ok == overflow || remaining || f.invalid || frames != 4 || bytes != 68 ||
        f.output.size() != (overflow ? 0 : 4)) {
      *detail = "activation metadata 4/+1 did not fail closed and release held frames";
      return false;
    }
    for (size_t i = 0; i < f.output.size(); ++i)
      if (f.output[i].run_id != i + 1 || f.output[i].type != v8host::RunEnvelopeType::kResult ||
          f.output[i].disposition != v8host::RunEnvelopeDisposition::kCompleted)
        return false;
  }
  f.output.clear();
  if (!f.Batch({GuestStart("host.postMessage('not-started');"), GuestRelay(10)}, true, &bytes, &frames) ||
      !f.output.empty()) {
    *detail = "closing iteration began or replayed pending START";
    return false;
  }
  if (!f.Batch({GuestRelay(10, 99)}, false, &bytes, &frames) || !f.output.empty() || bytes || frames)
    return false;
  return true;
}
struct RouterFixture {
  router::Connection conn;
  sbox_broker_api api = {sizeof(api), &Spawn, &Post, &Close, &Wait};
  std::unique_ptr<router::Router> service;
  router::Worker *worker = nullptr;
  struct Handle {
    RouterFixture *fixture;
    router::Worker *worker;
    std::atomic<bool> closed{false};
    Handle(RouterFixture *f, router::Worker *w) : fixture(f), worker(w) {}
  };
  std::vector<std::unique_ptr<Handle>> handles;
  std::vector<v8host::RunEnvelope> posts;
  std::atomic<unsigned> spawns{0}, closes{0}, waits{0}, post_after_close{0}, close_before_removal{0};
  bool early = false, before_publication = false, fail_post = false, fail_spawn = false, stop_during_spawn = false;
  HANDLE wait_entered = nullptr, wait_release = nullptr;
  RouterFixture() {
    OpenLocal(conn);
    v8host::HeldFile image;
    DWORD error;
    v8host::OpenImmutableFile(ExecutableDirectory() + L"\\v8jsisb.dll", &image, &error);
    service = std::make_unique<router::Router>(BrokerMode::kDedicated, reinterpret_cast<sbox_broker>(this),
        &api, ExecutableDirectory(), image.machine());
  }
  ~RouterFixture() {
    if (wait_release)
      ::SetEvent(wait_release);
    service->Close(conn);
    if (wait_entered)
      ::CloseHandle(wait_entered);
    if (wait_release)
      ::CloseHandle(wait_release);
  }
  static sbox_status SBOX_CALL Spawn(sbox_broker broker, const void *data, size_t size,
      sbox_message_cb callback, void *context, sbox_broker_worker *handle) {
    auto &f = *reinterpret_cast<RouterFixture *>(broker);
    ++f.spawns;
    v8host::V8HostSpawnConfigV1 config;
    if (!v8host::V8HostSpawnConfigV1::Decode(static_cast<const uint8_t *>(data), size, &config) ||
        (f.fail_spawn && !f.early))
      return sbox_error;
    f.worker = static_cast<router::Worker *>(context);
    if (f.early) {
      const uint8_t startup[] = {1, 0, 0, 0}, security[] = {2, 0, 0, 0};
      callback(context, sbox_msg_lifecycle, startup, 4);
      callback(context, sbox_msg_lifecycle, security, 4);
      f.before_publication = !f.worker->handle && f.posts.empty() && bool(f.worker->engine_image);
    }
    if (f.fail_spawn)
      return sbox_error;
    if (f.stop_during_spawn)
      f.conn.Stop();
    f.handles.push_back(std::make_unique<Handle>(&f, f.worker));
    *handle = reinterpret_cast<sbox_broker_worker>(f.handles.back().get());
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Post(sbox_broker_worker handle, sbox_msg_kind kind, const void *data, size_t size) {
    auto &f = *reinterpret_cast<Handle *>(handle)->fixture;
    if (reinterpret_cast<Handle *>(handle)->closed)
      ++f.post_after_close;
    v8host::RunEnvelope env;
    if (f.fail_post || kind != sbox_msg_binary || !v8host::DecodeRunEnvelope(static_cast<const uint8_t *>(data), size, &env))
      return sbox_error;
    f.posts.push_back(std::move(env));
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Close(sbox_broker_worker handle) {
    auto &f = *reinterpret_cast<Handle *>(handle)->fixture;
    ++f.closes;
    reinterpret_cast<Handle *>(handle)->closed = true;
    std::lock_guard<std::mutex> lock(f.conn.mutex);
    auto *worker = reinterpret_cast<Handle *>(handle)->worker;
    if (!worker || f.conn.sessions.contains(worker->session->session_id) || !worker->session->runs.empty())
      ++f.close_before_removal;
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Wait(sbox_broker_worker handle, int32_t *code) {
    auto &f = *reinterpret_cast<Handle *>(handle)->fixture;
    ++f.waits;
    if (f.wait_entered)
      ::SetEvent(f.wait_entered);
    if (f.wait_release)
      ::WaitForSingleObject(f.wait_release, INFINITE);
    *code = 0;
    return sbox_ok;
  }
  bool Create() {
    return LocalRoute(*service, conn, protocol::BuildCreateSessionFrame(ControlHeader(1), LogicalConfig()));
  }
  bool Start(uint32_t id, protocol::StartRunPayload inputs = {}) {
    inputs.tier_override = inputs.tier_override == 0 ? -1 : inputs.tier_override;
    if (inputs.guest_payload.empty())
      inputs.guest_payload = {'x'};
    return LocalRoute(*service, conn, protocol::BuildStartRunFrame(ControlHeader(1 + id, 1, id), inputs));
  }
  bool Relay(uint32_t id, size_t size, uint8_t byte = 1) {
    auto h = ControlHeader(0, 1, id);
    h.type = protocol::MessageType::RELAY_TO_WORKER;
    std::vector<uint8_t> body(size, byte);
    return LocalRoute(*service, conn, protocol::BuildRelayFrame(h, sbox_msg_binary, body.data(), body.size()));
  }
  void Phase(uint8_t phase, size_t size = 4) {
    const uint8_t bytes[] = {phase, 0, 0, 0, 0};
    router::Worker::OnMessage(worker, sbox_msg_lifecycle, bytes, size);
    service->Pump(conn);
  }
  void Terminal(uint32_t id, v8host::RunEnvelopeType type = v8host::RunEnvelopeType::kResult) {
    v8host::RunEnvelope env;
    env.type = type;
    env.run_id = id;
    env.status_code = static_cast<uint32_t>(protocol::StatusCode::ERROR_INTERNAL);
    auto bytes = v8host::EncodeRunEnvelope(env);
    router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
    service->Pump(conn);
  }
};
bool QueuedCancelsFirst(std::string *detail) {
  for (bool ready : {false, true}) {
    RouterFixture f;
    f.early = ready;
    if (!f.Create() || !f.Start(1) || !f.Start(2) || !f.Relay(2, 32)) return false;
    auto *worker = f.worker;
    auto &session = *worker->session;
    auto *run = session.runs.at(2).get();
    auto removed = std::make_shared<bool>(false);
    session.terminal_removed = [&, removed, run, worker] {
      *removed = !session.runs.contains(2) && run->held_relays.empty() && !run->queued_relay_bytes &&
          std::find(worker->pending_run_ids.begin(), worker->pending_run_ids.end(), 2) == worker->pending_run_ids.end();
    };
    DrainLocal(f.conn);
    const auto cancel = protocol::BuildCancelRunFrame(ControlHeader(9, 1, 2));
    if (!LocalRoute(*f.service, f.conn, cancel)) return false;
    // Production reclaims the run once the strand has no contenders.
    session.terminal_removed = {};
    protocol::FrameHeader h;
    std::vector<uint8_t> terminal;
    const uint8_t *payload = nullptr;
    size_t size = 0;
    protocol::ResultPayload result;
    if (!f.conn.TakeOutput(&terminal)) return false;
    f.conn.CompleteOutput(terminal.size());
    if (!*removed || session.runs.contains(2) ||
        protocol::DecodeAndValidateFrame(terminal.data(), terminal.size(), &h, &payload, &size) != protocol::DecodeStatus::kOk ||
        h.type != protocol::MessageType::RESULT || h.run_id != 2 || !protocol::DecodeResultPayload(payload, size, &result) ||
        result.disposition != protocol::ResultDisposition::kCancelled ||
        !PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK || h.request_id != 9 ||
        !f.conn.out_queue.empty()) {
      *detail = "queued CANCEL did not remove, credit and terminalize before ACK";
      return false;
    }
    if (!LocalRoute(*f.service, f.conn, cancel) || !PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK ||
        !f.conn.out_queue.empty()) return false;
    if (!ready) { f.Phase(1); f.Phase(2); }
    f.Terminal(1);
    for (const auto &post : f.posts)
      if (post.run_id == 2) { *detail = "cancelled queued run posted to worker"; return false; }
    if (f.posts.size() != 1 || worker->engine_busy_run_id || !worker->pending_run_ids.empty()) return false;
  }
  return true;
}
bool TimeoutCloseOrder(std::string *detail) {
  for (int winner = 0; winner != 4; ++winner) {
    RouterFixture f;
    auto now = std::chrono::steady_clock::time_point{} + std::chrono::seconds(1);
    f.service->test_now = [&] { return now; };
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.early = true;
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1) || !f.Start(2) || !f.Relay(2, 32))
      return false;
    auto *worker = f.worker;
    auto &session = *worker->session;
    std::vector<router::Run *> runs;
    for (auto &[id, run] : session.runs) runs.push_back(run.get());
    auto removed_first = std::make_shared<bool>(true);
    session.terminal_removed = [&, removed_first] {
      *removed_first = *removed_first && !f.conn.sessions.contains(1) && session.runs.empty();
    };
    DrainLocal(f.conn);
    const auto cancel = protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1));
    if (!LocalRoute(*f.service, f.conn, cancel) || !LocalRoute(*f.service, f.conn, cancel)) return false;
    DrainLocal(f.conn);
    now += std::chrono::milliseconds(4999);
    f.service->Pump(f.conn);
    if (f.conn.sessions.size() != 1 || f.closes || f.waits || f.posts.size() != 2 ||
        f.posts[1].type != v8host::RunEnvelopeType::kCancel || f.service->WakeDelay(f.conn, INFINITE) != 1 ||
        !f.conn.out_queue.empty()) { *detail = "fallback fired early or duplicate CANCEL posted"; return false; }
    if (winner == 1) {
      session.terminal_removed = {};
      f.Terminal(1);
      if (worker->cancel_deadline != std::chrono::steady_clock::time_point{} || f.posts.size() != 4) return false;
      DrainLocal(f.conn);
    } else if (winner == 2) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(10)))) return false;
      DrainLocal(f.conn);
    } else if (winner == 3) {
      // Connection Close joins; release the fake wait before entering it.
      ::SetEvent(f.wait_release);
      f.service->Close(f.conn);
    }
    now += std::chrono::milliseconds(1);
    f.service->Pump(f.conn);
    if (winner == 0) {
      if (::WaitForSingleObject(f.wait_entered, 5000) != WAIT_OBJECT_0 || !*removed_first ||
          !f.conn.sessions.empty() || f.conn.retired_sessions.size() != 1 || !session.runs.empty() ||
          f.posts.size() != 2 || f.closes != 1 || f.waits != 1 || f.close_before_removal || f.post_after_close ||
          worker->cancel_deadline != std::chrono::steady_clock::time_point{}) {
        *detail = "expiry did not remove all ids before CAS/close and retain held cleanup";
        return false;
      }
      for (auto *run : runs)
        if (run->state != router::RunState::kWorkerExited || !run->held_relays.empty() || run->queued_relay_bytes)
          return false;
      protocol::FrameHeader h;
      if (!PopFrame(f.conn, &h) || h.type != protocol::MessageType::WORKER_EXIT || !f.conn.out_queue.empty()) {
        *detail = "client terminal not delivered at timer fire while wait held"; return false;
      }
    } else if (!f.conn.out_queue.empty() || (winner == 1 && (f.closes || f.waits))) return false;
    for (int i = 0; i < 3; ++i) { now += std::chrono::seconds(5); f.service->Pump(f.conn); }
    if (!f.conn.out_queue.empty() || f.service->WakeDelay(f.conn, INFINITE) != INFINITE) return false;
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (!f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || f.closes != 1 || f.waits != 1 ||
        f.close_before_removal || f.post_after_close) return false;
  }
  return true;
}
bool ReapingSessionQuota(std::string *detail) {
  RouterFixture f;
  f.early = true;
  f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.wait_release) return false;
  for (uint32_t id = 1; id <= protocol::kMaxSessionsPerConnection; ++id) {
    protocol::StartRunPayload start;
    start.tier_override = -1;
    start.guest_payload = {'x'};
    if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(id * 3, id), LogicalConfig())) ||
        !LocalRoute(*f.service, f.conn, protocol::BuildStartRunFrame(ControlHeader(id * 3 + 1, id, 1), start)) ||
        !LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(id * 3 + 2, id)))) return false;
    DrainLocal(f.conn);
  }
  if (f.conn.retired_sessions.size() != protocol::kMaxSessionsPerConnection ||
      ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0) {
    *detail = "bounded reaping churn disconnected healthy connection"; return false;
  }
  if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(100, 33), LogicalConfig())))
    return false;
  protocol::FrameHeader h;
  protocol::StatusCode status;
  if (!PopFrame(f.conn, &h, &status) || h.type != protocol::MessageType::ERROR || status != protocol::StatusCode::ERROR_QUOTA ||
      f.conn.sessions.contains(33) || ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0) return false;
  ::SetEvent(f.wait_release);
  for (const auto &session : f.conn.retired_sessions)
    if (::WaitForSingleObject(session->worker->cleanup, 5000) != WAIT_OBJECT_0) return false;
  if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(101, 33), LogicalConfig())) ||
      !PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK || !PopFrame(f.conn, &h) ||
      h.type != protocol::MessageType::SESSION_READY || !f.conn.retired_sessions.empty() || f.closes != 32 || f.waits != 32 ||
      f.close_before_removal || f.post_after_close) {
    *detail = "joined reapers did not release admission credit"; return false;
  }
  return true;
}
bool MailboxPumpBound(std::string *detail) {
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  auto *worker = f.worker;
  auto bytes = v8host::EncodeRunEnvelope(GuestRelay(1));
  router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
  size_t copied = 0;
  worker->mailbox_readout = [&] {
    ++copied;
    router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
  };
  f.service->Pump(f.conn);
  worker->mailbox_readout = {};
  if (copied != worker->mailbox.size() || worker->mailbox_tail - worker->mailbox_head != 1 ||
      ::WaitForSingleObject(f.conn.worker_wake, 0) != WAIT_OBJECT_0 || f.closes || worker->mailbox_failed ||
      f.conn.out_queue.size() != worker->mailbox.size()) {
    *detail = "producer replenishment did not yield bounded Pump and re-signal"; return false;
  }
  f.service->Pump(f.conn);
  return worker->mailbox_tail == worker->mailbox_head && f.conn.out_queue.size() == worker->mailbox.size() + 1;
}
bool TimeoutPendingRead(std::string *detail) {
  RouterFixture f;
  f.early = true;
  std::atomic<int64_t> ticks{1000};
  f.service->test_now = [&] {
    return std::chrono::steady_clock::time_point{} + std::chrono::milliseconds(ticks.load());
  };
  if (!f.Create() || !f.Start(1) || !LocalRoute(*f.service, f.conn,
      protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1)))) return false;
  DrainLocal(f.conn);
  struct Handles {
    HANDLE pipe = INVALID_HANDLE_VALUE, client = INVALID_HANDLE_VALUE;
    HANDLE pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pumped = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    ~Handles() {
      if (pipe != INVALID_HANDLE_VALUE) ::CloseHandle(pipe);
      if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
      if (pending) ::CloseHandle(pending);
      if (pumped) ::CloseHandle(pumped);
    }
  } h;
  const auto name = LR"(\\.\pipe\v8host-timeout-read-)" + std::to_wstring(::GetCurrentProcessId());
  h.pipe = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr);
  h.client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED, nullptr);
  OVERLAPPED connect = {};
  connect.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  bool connected = h.pipe != INVALID_HANDLE_VALUE && h.client != INVALID_HANDLE_VALUE && h.pending && h.pumped &&
      connect.hEvent && (::ConnectNamedPipe(h.pipe, &connect) || ::GetLastError() == ERROR_PIPE_CONNECTED);
  if (connect.hEvent) ::CloseHandle(connect.hEvent);
  if (!connected) return false;
  f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.wait_entered || !f.wait_release) return false;
  f.conn.pipe = h.pipe;
  f.conn.read_pending = h.pending;
  f.conn.dispatcher = f.service.get();
  f.service->test_pump_complete = [&] { ::SetEvent(h.pumped); };
  bool read_ok = true;
  std::thread reader([&] { uint8_t byte; DWORD size; read_ok = f.conn.ReadFrame(&byte, 1, &size, INFINITE); });
  bool passed = ::WaitForSingleObject(h.pending, 5000) == WAIT_OBJECT_0;
  if (passed) {
    ticks = 5999;
    ::SetEvent(f.conn.worker_wake);
    passed = ::WaitForSingleObject(h.pumped, 5000) == WAIT_OBJECT_0;
  }
  if (passed) {
    passed = f.conn.sessions.size() == 1 && !f.closes && !f.waits && f.conn.out_queue.empty();
    ticks = 6000;
    ::SetEvent(f.conn.worker_wake);
    passed = passed && ::WaitForSingleObject(f.wait_entered, 5000) == WAIT_OBJECT_0;
  }
  f.conn.Stop();
  reader.join();
  f.conn.pipe = INVALID_HANDLE_VALUE;
  f.conn.read_pending = nullptr;
  f.service->test_pump_complete = {};
  f.conn.dispatcher = nullptr;
  protocol::FrameHeader frame;
  passed = passed && !read_ok && !f.conn.active_io && f.conn.sessions.empty() && f.conn.retired_sessions.size() == 1 &&
      PopFrame(f.conn, &frame) && frame.type == protocol::MessageType::WORKER_EXIT && f.conn.out_queue.empty() &&
      f.closes == 1 && f.waits == 1 && !f.close_before_removal;
  ::SetEvent(f.wait_release);
  f.service->Close(f.conn);
  if (!passed || !f.conn.retired_sessions.empty()) {
    *detail = "pending pipe read did not service explicit cancel clock and join before teardown"; return false;
  }
  return true;
}
bool PopWorkerExit(router::Connection& conn, uint32_t session_id = 1) {
  protocol::FrameHeader h;
  return PopFrame(conn, &h) && h.type == protocol::MessageType::WORKER_EXIT &&
      h.session_id == session_id && h.run_id == 0 && h.request_id == 0 && conn.out_queue.empty();
}
bool LifecycleAbi5(std::string* detail) {
  bool ok = SBOX_ABI_VERSION == 5u;
  for (const auto* dll : {L"v8host.dll", L"v8host_abi4_plugin.dll"}) {
    HMODULE module = ::LoadLibraryExW((ExecutableDirectory() + L"\\" + dll).c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    if (!module)
      return false;
    auto entry = reinterpret_cast<sbox_plugin_main_fn>(::GetProcAddress(module, SBOX_PLUGIN_ENTRY));
    const bool old = std::wstring(dll) == L"v8host_abi4_plugin.dll";
    const sbox_plugin* plugin = nullptr;
    ok = entry && entry(old ? 4u : 5u, &plugin) == sbox_ok && plugin &&
        plugin->abi_version == (old ? 4u : 5u) && plugin->configure && plugin->broker_run &&
        plugin->warmup && plugin->run && plugin->shutdown && ok;
    plugin = nullptr;
    ok = entry && entry(old ? 5u : 4u, &plugin) == sbox_error_version && !plugin && ok;
    ::FreeLibrary(module);
  }
  DWORD code = 0;
  const std::wstring command = L"\"" + ExecutableDirectory() +
      L"\\sbox.exe\" --broker --plugin v8host_abi4_plugin.dll";
  ok = v8host::test::RunProcess(command, &code) && code == 3 && ok;
  if (!ok) *detail = "matching ABI/4-5 rejection";
  return ok;
}
bool CoreLifecycleCase(const wchar_t* args, std::string* detail) {
  DWORD code = 1;
  const std::wstring command = L"\"" + ExecutableDirectory() +
      L"\\sbox_lifecycle_tests.exe\" " + args;
  if (!v8host::test::RunProcess(command, &code) || code) {
    *detail = "production core fixture failed";
    return false;
  }
  return true;
}
bool ExitFinalDrain(std::string* detail) {
  if (!CoreLifecycleCase(L"--suite=reader --case=final-drain", detail))
    return false;
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1) || !f.Start(2))
    return false;
  DrainLocal(f.conn);
  v8host::RunEnvelope env;
  env.type = v8host::RunEnvelopeType::kResult;
  env.run_id = 1;
  const auto bytes = v8host::EncodeRunEnvelope(env);
  router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
  const uint8_t exit[] = {SBOX_LIFECYCLE_EXIT,0,0,0};
  router::Worker::OnMessage(f.worker, sbox_msg_lifecycle, exit, 4);
  f.service->Pump(f.conn);
  protocol::FrameHeader h;
  const bool ordered = PopFrame(f.conn, &h) && h.type == protocol::MessageType::RESULT && h.run_id == 1 &&
      PopWorkerExit(f.conn) && f.conn.sessions.empty() && f.posts.size() == 1;
  f.service->Close(f.conn);
  return ordered && f.closes == 1 && f.waits == 1 && !f.close_before_removal && !f.post_after_close &&
      f.conn.retired_sessions.empty();
}
bool SmokeLifecycleTwo(std::string* d) { return CoreLifecycleCase(L"--suite=smoke --case=lifecycle-two", d); }
bool WorkerKindGuard(std::string* d) { return CoreLifecycleCase(L"--suite=worker --case=post-kind-guard", d); }
bool ExitFactOrigin(std::string *detail) {
  if (!CoreLifecycleCase(L"--suite=reader --case=origin", detail))
    return false;
  RouterFixture f;
  f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.Create() || !f.Start(1))
    return false;
  f.Phase(SBOX_LIFECYCLE_STARTUP);
  f.Phase(SBOX_LIFECYCLE_EXIT);
  if (!f.conn.sessions.empty() || ::WaitForSingleObject(f.wait_entered, 5000) != WAIT_OBJECT_0 ||
      f.closes != 1 || f.close_before_removal || f.waits != 1) {
    *detail = "exit ids/cleanup handoff";
    return false;
  }
  f.Phase(SBOX_LIFECYCLE_EXIT);
  protocol::FrameHeader h;
  unsigned exits = 0, terminals = 0;
  while (PopFrame(f.conn, &h)) {
    exits += h.type == protocol::MessageType::WORKER_EXIT;
    terminals += h.type == protocol::MessageType::RESULT || h.type == protocol::MessageType::RUN_ERROR;
  }
  return exits == 1 && terminals == 0 && f.waits == 1 && !f.post_after_close;
}
bool ExitCleanupOrderings(std::string* detail) {
  if (!CoreLifecycleCase(L"--suite=reader --case=stop-suppresses-exit", detail))
    return false;
  for (int order = 0; order != 3; ++order) {
    RouterFixture f;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.early = true;
    if (!f.Create() || !f.Start(1) || f.closes || f.waits || f.worker->wait_called)
      return false;
    DrainLocal(f.conn);
    auto* worker = f.worker;
    if (order == 0)
      f.Phase(SBOX_LIFECYCLE_EXIT);
    if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(9))))
      return false;
    if (::WaitForSingleObject(f.wait_entered, 5000) != WAIT_OBJECT_0)
      return false;
    if (order == 1)
      f.Phase(SBOX_LIFECYCLE_EXIT);
    protocol::FrameHeader h;
    // The session or explicit-close terminal precedes the ACK.
    bool terminal = PopFrame(f.conn, &h) && h.type == (order == 0
        ? protocol::MessageType::WORKER_EXIT : protocol::MessageType::RESULT);
    if (!terminal || !PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK || !f.conn.out_queue.empty() ||
        !f.conn.sessions.empty() || !worker->session->runs.empty() || f.closes != 1 || f.waits != 1 ||
        f.close_before_removal || f.post_after_close)
      return false;
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (!f.conn.retired_sessions.empty() || f.closes != 1 || f.waits != 1)
      return false;
  }
  return true;
}
bool CoordinatorTerminalHoldsNext(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1))
    return false;
  f.Phase(1); f.Phase(2);
  if (f.posts.size() != 1 || !f.Start(2) || !f.Relay(2, 1, 7) || !f.Relay(1, 65513))
    return false;
  if (f.worker->engine_busy_run_id != 1 || f.worker->active_run_id != 0 || f.posts.size() != 2 ||
      f.posts.back().type != v8host::RunEnvelopeType::kCancel || f.conn.sessions.at(1)->runs.contains(1)) {
    *detail = "logical terminal retired engine busy or dispatched successor";
    return false;
  }
  f.service->Pump(f.conn); f.service->Pump(f.conn);
  if (f.posts.size() != 2 || !f.Relay(2, 1, 8))
    return false;
  unsigned terminals = 0;
  protocol::FrameHeader h;
  std::vector<uint8_t> bytes;
  while (f.conn.TakeOutput(&bytes)) {
    f.conn.CompleteOutput(bytes.size());
    const uint8_t *payload; size_t size;
    if (protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &h, &payload, &size) != protocol::DecodeStatus::kOk)
      return false;
    if (h.type == protocol::MessageType::RUN_ERROR) {
      protocol::ErrorPayload error;
      if (!protocol::DecodeErrorPayload(payload, size, &error) || error.status_code != protocol::StatusCode::ERROR_QUOTA ||
          h.run_id != 1 || h.request_id != 0)
        return false;
      ++terminals;
    }
  }
  f.Terminal(1);
  if (terminals != 1 || f.posts.size() != 5 || f.posts[2].type != v8host::RunEnvelopeType::kStart ||
      f.posts[2].run_id != 2 || f.posts[3].payload != std::vector<uint8_t>{7} ||
      f.posts[4].payload != std::vector<uint8_t>{8} || f.worker->engine_busy_run_id != 2 || !f.conn.out_queue.empty()) {
    *detail = "late engine terminal/successor FIFO";
    return false;
  }
  f.Terminal(2);
  return f.worker->engine_busy_run_id == 0 && f.conn.out_queue.size() == 1;
}
bool CreateCloseLoop(std::string *detail) {
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  for (uint32_t id = 1; id <= 1000; ++id) {
    if (!LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(id * 2, id), LogicalConfig())) ||
        !LocalRoute(service, conn, protocol::BuildCloseSessionFrame(ControlHeader(id * 2 + 1, id))) ||
        !conn.sessions.empty() || !conn.retired_sessions.empty()) {
      *detail = "empty retired session retained at iteration " + std::to_string(id);
      return false;
    }
    DrainLocal(conn);
  }
  return conn.highest_session_id == 1000 && conn.request_cache.size() <= 256;
}
bool RelayHoldBeforeReady(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1) || !f.Relay(1, 2, 9) || !f.Relay(1, 3, 8) || !f.posts.empty() ||
      !f.worker->engine_image)
    return false;
  f.Phase(1);
  if (!f.posts.empty() || f.worker->engine_image || !f.worker->startup || f.worker->security)
    return false;
  f.Phase(2);
  if (f.posts.size() != 3 || f.posts[0].type != v8host::RunEnvelopeType::kStart ||
      f.posts[1].payload != std::vector<uint8_t>(2, 9) || f.posts[2].payload != std::vector<uint8_t>(3, 8)) {
    *detail = "relay hold/release order before readiness";
    return false;
  }
  return true;
}
bool RelayHoldNextRun(std::string *detail) {
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1) || !f.Start(2) || !f.Relay(2, 2, 9) || !f.Relay(2, 3, 8))
    return false;
  f.service->Pump(f.conn);
  if (f.posts.size() != 1 || f.worker->engine_busy_run_id != 1 || !f.before_publication)
    return false;
  f.Terminal(1);
  if (f.posts.size() != 4 || f.posts[1].type != v8host::RunEnvelopeType::kStart || f.posts[1].run_id != 2 ||
      f.posts[2].payload != std::vector<uint8_t>(2, 9) || f.posts[3].payload != std::vector<uint8_t>(3, 8)) {
    *detail = "nonselected relay FIFO";
    return false;
  }
  return true;
}
bool ReadinessProvenance(std::string *detail) {
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1) || !f.before_publication || f.spawns != 1 || !f.worker->startup ||
      !f.worker->security || f.worker->engine_image || f.posts.size() != 1)
    return false;
  DrainLocal(f.conn);
  f.Phase(1); f.Phase(2);
  if (!f.conn.out_queue.empty() || f.posts.size() != 1)
    return false;
  v8host::RunEnvelope spoof;
  spoof.type = v8host::RunEnvelopeType::kRelay;
  spoof.run_id = 1;
  spoof.relay_kind = sbox_msg_string;
  const std::string marker = "STARTUP_READY SECURITY_READY";
  spoof.payload.assign(marker.begin(), marker.end());
  auto bytes = v8host::EncodeRunEnvelope(spoof);
  router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
  f.service->Pump(f.conn);
  protocol::FrameHeader h;
  if (!PopFrame(f.conn, &h) || h.type != protocol::MessageType::RELAY_FROM_WORKER || !f.conn.out_queue.empty()) {
    *detail = "guest relay gained lifecycle authority";
    return false;
  }
  return true;
}
bool LifecycleWrongWorker(std::string *detail) {
  for (bool ready : {false, true}) {
    RouterFixture f;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1))
      return false;
    if (ready) {
      f.Phase(1);
      f.Phase(2);
    }
    DrainLocal(f.conn);
    auto *owner = f.worker;
    const size_t posts = f.posts.size();
    auto stale = std::make_unique<router::Worker>();
    stale->session = owner->session;
    const uint8_t phase[] = {1, 0, 0, 0};
    router::Worker::OnMessage(stale.get(), sbox_msg_lifecycle, phase, sizeof(phase));
    f.service->Pump(f.conn);
    if (::WaitForSingleObject(f.wait_entered, 3000) != WAIT_OBJECT_0 ||
        !f.conn.sessions.empty() || !owner->mailbox_failed || stale->mailbox_tail.load() - stale->mailbox_head.load() ||
        f.closes != 1 || f.waits != 1 || f.posts.size() != posts || !PopWorkerExit(f.conn) ||
        owner->startup != ready || owner->security != ready || bool(owner->engine_image) == ready) {
      *detail = "wrong-worker lifecycle did not fail closed before/after readiness";
      return false;
    }
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (f.closes != 1 || f.waits != 1 || !f.conn.retired_sessions.empty())
      return false;
  }
  return true;
}
bool LifecycleOrder(std::string *detail) {
  for (auto [phase, size] : std::vector<std::pair<uint8_t, size_t>>{{2,4},{0,4},{4,4},{1,3},{1,5}}) {
    RouterFixture f;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1))
      return false;
    DrainLocal(f.conn);
    auto *worker = f.worker;
    f.Phase(phase, size);
    if (::WaitForSingleObject(f.wait_entered, 3000) != WAIT_OBJECT_0 || !f.conn.sessions.empty() ||
        !worker->engine_image || f.closes != 1 || !f.posts.empty() || !PopWorkerExit(f.conn)) {
      *detail = "invalid lifecycle accepted or image released before cleanup";
      return false;
    }
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (f.waits != 1 || f.post_after_close != 0 || !f.conn.retired_sessions.empty())
      return false;
  }
  return true;
}
bool WorkerOutputZeroId(std::string *detail) {
  for (bool idle : {false, true}) {
    for (auto type : {v8host::RunEnvelopeType::kRelay, v8host::RunEnvelopeType::kResult}) {
      RouterFixture f;
      if (!f.Create() || !f.Start(1)) return false;
      f.Phase(1); f.Phase(2);
      if (idle) f.Terminal(1);
      DrainLocal(f.conn);
      auto env = GuestRelay(1, 0);
      env.type = type;
      auto bytes = v8host::EncodeRunEnvelope(env);
      router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
      f.service->Pump(f.conn);
      const bool rejected = f.conn.sessions.empty();
      f.service->Close(f.conn);
      if (!rejected || !f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || f.closes != 1 || f.waits != 1 ||
          f.close_before_removal || f.post_after_close || !PopWorkerExit(f.conn)) {
        *detail = "zero-id worker output was accepted while idle/busy";
        return false;
      }
    }
  }
  return true;
}
bool ProfileConflictInvalid(std::string *detail) {
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  for (uint32_t id : {2, 3}) {
    protocol::StartRunPayload start;
    start.tier_override = v8host::kTierTrusted;
    if (id == 2) {
      start.has_engine_override = true;
      start.engine_filename = "../engine.dll";
    } else {
      start.has_snapshot = true;
      start.snapshot_path = "../other.snapshot";
    }
    const bool accepted = f.Start(id, start);
    if (id == 2) {
      if (accepted || !f.conn.out_queue.empty()) {
        *detail = "malformed engine path bypassed the codec";
        return false;
      }
    } else {
      protocol::FrameHeader h;
      protocol::StatusCode code;
      if (!accepted || !PopFrame(f.conn, &h, &code) || h.type != protocol::MessageType::ERROR ||
          code != protocol::StatusCode::ERROR_BAD_STATE) {
        *detail = "tier conflict masked invalid snapshot inputs";
        return false;
      }
    }
    if (f.conn.sessions.at(1)->highest_run_id != 1 ||
        f.conn.sessions.at(1)->runs.size() != 1 || f.posts.size() != 1 || f.spawns != 1 || f.closes) {
      *detail = "tier conflict masked invalid profile inputs";
      return false;
    }
  }
  return true;
}
bool FirstRunBinding(std::string *detail) {
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1))
    return false;
  DrainLocal(f.conn);
  uint32_t id = 2;
  for (int which = 0; which < 3; ++which, ++id) {
    protocol::StartRunPayload start;
    start.tier_override = -1;
    if (which == 0)
      start.tier_override = v8host::kTierTrusted;
    else if (which == 1) {
      start.has_engine_override = true;
      start.engine_filename = "other.dll";
    } else {
      start.has_snapshot = true;
      start.snapshot_path = "other.snapshot";
    }
    if (!f.Start(id, start))
      return false;
    protocol::FrameHeader h;
    protocol::StatusCode code;
    if (!PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK ||
        !PopFrame(f.conn, &h, &code) || h.type != protocol::MessageType::RUN_ERROR ||
        code != protocol::StatusCode::ERROR_PROFILE_ALREADY_BOUND || h.run_id != id || h.request_id != 0 ||
        f.spawns != 1 || f.posts.size() != 1 || f.worker->engine_busy_run_id != 1 || f.conn.sessions.at(1)->profile.engine_dll != "v8jsisb.dll") {
      *detail = "profile conflict disturbed worker or terminal code";
      return false;
    }
  }
  f.Terminal(1);
  if (!f.Start(id) || f.posts.size() != 2 || f.posts.back().run_id != id || f.spawns != 1)
    return false;
  f.Terminal(id);
  return true;
}
bool StartAdmissionQuota(std::string *detail) {
  RouterFixture f;
  if (!f.Create())
    return false;
  DrainLocal(f.conn);
  for (uint32_t id = 1; id <= 4; ++id) {
    if (!f.Start(id))
      return false;
    DrainLocal(f.conn);
  }
  if (!f.Start(5))
    return false;
  protocol::FrameHeader h;
  protocol::StatusCode code;
  if (!PopFrame(f.conn, &h, &code) || h.type != protocol::MessageType::ERROR ||
      code != protocol::StatusCode::ERROR_QUOTA || f.conn.sessions.at(1)->runs.size() != 4 || f.spawns != 1) {
    *detail = "in-flight 4/+1 admission";
    return false;
  }
  return true;
}
bool EnvelopeSizeBoundary(std::string *detail) {
  if (!router::EnvelopeFits(v8host::RunEnvelopeType::kStart, 65516) ||
      router::EnvelopeFits(v8host::RunEnvelopeType::kStart, 65517) ||
      !router::EnvelopeFits(v8host::RunEnvelopeType::kRelay, 65512) ||
      router::EnvelopeFits(v8host::RunEnvelopeType::kRelay, 65513) ||
      router::EnvelopeFits(v8host::RunEnvelopeType::kRelay, SIZE_MAX))
    return false;
  RouterFixture f;
  f.early = true;
  if (!f.Create() || !f.Start(1) || !f.Relay(1, 65512) || f.posts.size() != 2 ||
      f.posts.back().payload.size() != 65512)
    return false;
  DrainLocal(f.conn);
  if (!f.Relay(1, 65513))
    return false;
  protocol::FrameHeader h;
  protocol::StatusCode code;
  if (!PopFrame(f.conn, &h, &code) || h.type != protocol::MessageType::RUN_ERROR || h.request_id != 0 ||
      code != protocol::StatusCode::ERROR_QUOTA || f.posts.back().type != v8host::RunEnvelopeType::kCancel) {
    *detail = "encoded oversize did not terminalize addressed run";
    return false;
  }
  return true;
}
bool TerminalContenderOrderings(std::string *detail) {
  // Each first/second pair has a held callback-reader join, not a timing race.
  for (int first = 0; first < 5; ++first) for (int second = 0; second < 5; ++second) {
    RouterFixture f; f.early = true;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    auto *worker = f.worker;
    std::atomic<unsigned> removals{0};
    worker->session->terminal_removed = [&] { ++removals; };
    bool disconnected = false, passed = true;
    std::thread disconnect;
    auto actor = [&](int action) {
      if (action == 4 && !disconnected) {
        disconnected = true;
        disconnect = std::thread([&] { f.service->Close(f.conn); });
        passed = passed && ::WaitForSingleObject(f.wait_entered, 5000) == WAIT_OBJECT_0;
      } else if (action == 3 && !disconnected && f.conn.sessions.contains(1)) {
        passed = passed && LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(20)));
      } else if (action <= 2) {
        if (action == 2) {
          const uint8_t phase[] = {SBOX_LIFECYCLE_EXIT, 0, 0, 0};
          router::Worker::OnMessage(worker, sbox_msg_lifecycle, phase, 4);
        } else {
          v8host::RunEnvelope env; env.run_id = 1;
          env.type = action == 0 ? v8host::RunEnvelopeType::kResult : v8host::RunEnvelopeType::kRunError;
          auto bytes = v8host::EncodeRunEnvelope(env);
          router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
        }
        if (!disconnected) f.service->Pump(f.conn);
      }
      if (worker->close_called)
        passed = passed && ::WaitForSingleObject(f.wait_entered, 5000) == WAIT_OBJECT_0 &&
            !f.conn.sessions.contains(1) && worker->session->runs.empty();
    };
    actor(first); actor(second);
    if (!worker->close_called) actor(3);
    // Late facts cannot rebind while the callback context is still retained.
    const size_t tail = worker->mailbox_tail;
    for (int action = 0; action < 3; ++action) actor(action);
    passed = passed && worker->mailbox_tail == tail && removals == 2 && !worker->engine_busy_run_id &&
        worker->cancel_deadline == std::chrono::steady_clock::time_point{} &&
        worker->retry_deadline == std::chrono::steady_clock::time_point{};
    ::SetEvent(f.wait_release);
    if (disconnect.joinable()) disconnect.join(); else f.service->Close(f.conn);
    unsigned terminals[3] = {}, exits = 0;
    protocol::FrameHeader h;
    while (PopFrame(f.conn, &h)) {
      if (h.type == protocol::MessageType::RESULT || h.type == protocol::MessageType::RUN_ERROR) {
        if (!h.run_id || h.run_id > 2 || ++terminals[h.run_id] > 1) passed = false;
      }
      if (h.type == protocol::MessageType::WORKER_EXIT && ++exits > 1) passed = false;
    }
    if (!passed || !f.conn.CompleteZero() || f.closes != 1 || f.waits != 1 || f.close_before_removal || f.post_after_close ||
        f.posts.size() > 2) {
      *detail = "terminal contender pair " + std::to_string(first) + "/" + std::to_string(second); return false;
    }
  }
  return true;
}
bool CompleteZeroDrain(std::string *detail) {
  RouterFixture f; f.early = true;
  std::atomic<int64_t> ticks{1000}; std::atomic<unsigned> clocks{0}, posts{0};
  f.service->test_now = [&] { ++clocks; return std::chrono::steady_clock::time_point{} + std::chrono::milliseconds(ticks.load()); };
  f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1)) return false;
  f.service->test_post = [&](const std::vector<uint8_t> &) { ++posts; return router::PostOutcome::kNotWritten; };
  if (!LocalRoute(*f.service, f.conn, protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1)))) return false;
  DrainLocal(f.conn);
  auto *worker = f.worker;
  if (f.conn.CompleteZero() || worker->cancel_deadline == std::chrono::steady_clock::time_point{} ||
      worker->retry_deadline == std::chrono::steady_clock::time_point{}) return false;
  f.conn.writer_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.conn.writer_release || !f.conn.StartWriter()) return false;
  f.conn.dispatcher = f.service.get();
  HANDLE joined = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!joined) return false;
  std::thread closer([&] { f.service->Close(f.conn); ::SetEvent(joined); });
  const bool entered = ::WaitForSingleObject(f.wait_entered, 5000) == WAIT_OBJECT_0;
  bool passed = entered && ::WaitForSingleObject(joined, 0) == WAIT_TIMEOUT && !f.conn.CompleteZero() &&
      f.conn.sessions.empty() && f.conn.retired_sessions.size() == 1 && worker->session->runs.empty() &&
      worker->cancel_deadline == std::chrono::steady_clock::time_point{} &&
      worker->retry_deadline == std::chrono::steady_clock::time_point{};
  const unsigned calls = clocks;
  ticks = 100000;
  const uint8_t exit[] = {SBOX_LIFECYCLE_EXIT, 0, 0, 0};
  router::Worker::OnMessage(worker, sbox_msg_lifecycle, exit, 4);
  passed = passed && clocks == calls && posts == 1;
  ::SetEvent(f.wait_release); closer.join(); ::CloseHandle(joined);
  // A registered writer prevents zero even after worker cleanup joins.
  passed = passed && !f.conn.CompleteZero() && f.conn.retired_sessions.empty() && !f.conn.dispatcher;
  f.conn.JoinWriter(); ::CloseHandle(f.conn.writer_release); f.conn.writer_release = nullptr;
  f.conn.ClearOutput();
  if (!passed || !f.conn.CompleteZero() || f.conn.writers_started != 1 || f.conn.writers_joined != 1 ||
      f.closes != 1 || f.waits != 1 || f.post_after_close || f.close_before_removal) {
    *detail = "cleanup/timer/retry/writer/clock borrower escaped joined zero"; return false;
  }
  return true;
}
bool JoinedTeardown(std::string *detail) {
  RouterFixture f; f.early = true;
  f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!f.wait_entered || !f.wait_release) return false;
  uint32_t request = 0;
  for (uint32_t id = 1; id <= 100; ++id) {
    ::ResetEvent(f.wait_entered); ::ResetEvent(f.wait_release);
    if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(++request, id), LogicalConfig())))
      return false;
    protocol::StartRunPayload start; start.tier_override = -1; start.guest_payload = {'x'};
    if (!LocalRoute(*f.service, f.conn, protocol::BuildStartRunFrame(ControlHeader(++request, id, 1), start))) return false;
    auto *worker = f.worker;
    if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(++request, id))) ||
        ::WaitForSingleObject(f.wait_entered, 5000) != WAIT_OBJECT_0 || f.conn.retired_sessions.size() != 1) return false;
    HANDLE cleanup = worker->cleanup;
    ::SetEvent(f.wait_release);
    if (::WaitForSingleObject(cleanup, 5000) != WAIT_OBJECT_0) return false;
    f.service->Pump(f.conn); DrainLocal(f.conn);
    if (!f.conn.retired_sessions.empty() || !f.conn.sessions.empty() || f.conn.in_relay_bytes || f.conn.out_relay_bytes ||
        f.service->WakeDelay(f.conn, INFINITE) != INFINITE) {
      *detail = "churn retained joined object/task or deadline"; return false;
    }
  }
  f.service->Close(f.conn);
  return f.conn.CompleteZero() && f.closes == 100 && f.waits == 100 && !f.post_after_close && !f.close_before_removal;
}
struct PressurePipe {
  HANDLE server = INVALID_HANDLE_VALUE, client = INVALID_HANDLE_VALUE;
  HANDLE paused = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE resumed = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  bool Open(bool overlapped = false) {
    const auto name = LR"(\\.\pipe\v8host-pressure-)" + std::to_wstring(::GetCurrentProcessId());
    server = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr);
    client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, overlapped ? FILE_FLAG_OVERLAPPED : 0, nullptr);
    OVERLAPPED connect = {}; connect.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const bool ok = server != INVALID_HANDLE_VALUE && client != INVALID_HANDLE_VALUE && paused && resumed && pending &&
        connect.hEvent && (::ConnectNamedPipe(server, &connect) || ::GetLastError() == ERROR_PIPE_CONNECTED);
    if (connect.hEvent) ::CloseHandle(connect.hEvent);
    DWORD mode = PIPE_READMODE_MESSAGE;
    return ok && ::SetNamedPipeHandleState(client, &mode, nullptr, nullptr);
  }
  ~PressurePipe() {
    if (server != INVALID_HANDLE_VALUE) ::CloseHandle(server);
    if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
    if (paused) ::CloseHandle(paused);
    if (resumed) ::CloseHandle(resumed);
    if (pending) ::CloseHandle(pending);
  }
};
bool PressureTransfer(HANDLE pipe, bool write, void *data, DWORD capacity, DWORD *size) {
  OVERLAPPED ov = {}; ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!ov.hEvent) return false;
  const BOOL started = write ? ::WriteFile(pipe, data, capacity, nullptr, &ov) :
      ::ReadFile(pipe, data, capacity, nullptr, &ov);
  const bool pending = !started && ::GetLastError() == ERROR_IO_PENDING;
  bool ok = started || (pending && ::WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0);
  if (ok) ok = ::GetOverlappedResult(pipe, &ov, size, FALSE) != FALSE;
  if (pending && !ok) { ::CancelIoEx(pipe, &ov); ::GetOverlappedResult(pipe, &ov, size, TRUE); }
  ::CloseHandle(ov.hEvent);
  return ok && (!write || *size == capacity);
}
bool PauseResume(std::string *detail) {
  RouterFixture f; f.early = true; PressurePipe pipe;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  for (size_t i = 0; i < protocol::kMaxControlQueueRequests - 1; ++i)
    if (!f.conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)))) return false;
  if (!pipe.Open(true) || !f.conn.ReadsPaused()) return false;
  f.conn.pipe = pipe.server; f.conn.dispatcher = f.service.get();
  f.conn.read_paused = pipe.paused; f.conn.read_resumed = pipe.resumed; f.conn.read_pending = pipe.pending;
  HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!release) return false;
  f.conn.writer_release = release;
  bool read = false; uint8_t byte = 0; DWORD size = 0;
  // A finite zero budget must never become an indefinite paused wait.
  if (f.conn.ReadFrame(&byte, 1, &size, 0) || f.conn.active_io || !f.conn.StartWriter()) {
    ::CloseHandle(release); return false;
  }
  ::ResetEvent(pipe.paused);
  std::thread reader([&] { read = f.conn.ReadFrame(&byte, 1, &size, INFINITE); });
  bool passed = ::WaitForSingleObject(pipe.paused, 5000) == WAIT_OBJECT_0 && f.conn.active_io == 0;
  auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
  if (passed) router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
  ::SetEvent(release);
  // Real writer progress: controls followed by active-run output, while the
  // strand services mailbox wakes independently of admitting a new pipe read.
  std::array<uint8_t, protocol::kMaxFrameSize> output;
  for (size_t i = 0; i < protocol::kMaxControlQueueRequests && passed; ++i) {
    DWORD count = 0; protocol::FrameHeader h; const uint8_t *body; size_t body_size;
    passed = PressureTransfer(pipe.client, false, output.data(), static_cast<DWORD>(output.size()), &count) &&
        protocol::DecodeAndValidateFrame(output.data(), count, &h, &body, &body_size) == protocol::DecodeStatus::kOk &&
        (i < protocol::kMaxControlQueueRequests - 1 ? h.type == protocol::MessageType::ACK :
            h.type == protocol::MessageType::RELAY_FROM_WORKER && h.run_id == 1 && output[count - 1] == 7);
  }
  passed = passed && ::WaitForSingleObject(pipe.resumed, 5000) == WAIT_OBJECT_0 &&
      ::WaitForSingleObject(pipe.pending, 5000) == WAIT_OBJECT_0;
  if (passed) {
    uint8_t expected = 7; DWORD written;
    passed = PressureTransfer(pipe.client, true, &expected, 1, &written);
  }
  if (!passed) f.conn.Stop();
  reader.join(); f.conn.Stop(); f.conn.JoinWriter();
  f.conn.writer_release = nullptr; ::CloseHandle(release);
  f.conn.pipe = INVALID_HANDLE_VALUE; f.conn.read_paused = f.conn.read_resumed = f.conn.read_pending = nullptr;
  if (!passed || !read || byte != 7 || size != 1 || f.conn.active_io) {
    *detail = "connection output pause blocked active-run writer progress or read resume"; return false;
  }
  f.service->Close(f.conn); f.conn.ClearOutput();
  return f.conn.CompleteZero();
}
// A real pending pipe read proves run-local pressure does not suppress intake.
bool ReadThroughPressure(RouterFixture &f, const std::vector<uint8_t> &frame) {
  PressurePipe pipe;
  if (!pipe.Open() || f.conn.ReadsPaused()) return false;
  f.conn.pipe = pipe.server; f.conn.dispatcher = f.service.get(); f.conn.read_pending = pipe.pending;
  std::vector<uint8_t> received(protocol::kMaxFrameSize); DWORD size = 0; bool read = false;
  std::thread reader([&] { read = f.conn.ReadFrame(received.data(), static_cast<DWORD>(received.size()), &size, INFINITE); });
  bool passed = ::WaitForSingleObject(pipe.pending, 5000) == WAIT_OBJECT_0;
  DWORD written = 0;
  if (passed) passed = ::WriteFile(pipe.client, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr) &&
      written == frame.size();
  if (!passed) f.conn.Stop();
  reader.join(); f.conn.pipe = INVALID_HANDLE_VALUE; f.conn.read_pending = nullptr;
  return passed && read && size == frame.size() && !f.conn.active_io &&
      LocalRoute(*f.service, f.conn, std::vector<uint8_t>(received.begin(), received.begin() + size));
}
bool RunPressureContainment(std::string *detail) {
  RouterFixture f; f.early = true;
  if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
  DrainLocal(f.conn);
  size_t bytes = protocol::kMaxQueuedRelayBytesPerRun;
  while (bytes) {
    const size_t part = (std::min)(bytes, size_t(protocol::kMaxFramePayload));
    if (part < 16 || !f.Relay(2, part - 16)) return false;
    bytes -= part;
  }
  auto h = ControlHeader(0, 1, 1); h.type = protocol::MessageType::RELAY_TO_WORKER;
  const uint8_t input = 9;
  if (!ReadThroughPressure(f, protocol::BuildRelayFrame(h, sbox_msg_binary, &input, 1)) ||
      f.posts.size() != 2 || f.posts.back().payload != std::vector<uint8_t>{9} || f.conn.ReadsPaused()) {
    *detail = "queued run held active-run input behind a connection pause"; return false;
  }
  if (!ReadThroughPressure(f, protocol::BuildCreateSessionFrame(ControlHeader(4, 2), LogicalConfig())) ||
      !f.conn.sessions.contains(2) || !f.Relay(2, 1)) return false;
  protocol::FrameHeader reply;
  bool quota = false;
  std::vector<uint8_t> output;
  while (f.conn.TakeOutput(&output)) {
    f.conn.CompleteOutput(output.size());
    const uint8_t *body; size_t size;
    if (protocol::DecodeAndValidateFrame(output.data(), output.size(), &reply, &body, &size) != protocol::DecodeStatus::kOk)
      return false;
    if (reply.type == protocol::MessageType::RUN_ERROR) {
      protocol::ErrorPayload payload;
      quota = protocol::DecodeErrorPayload(body, size, &payload) && reply.session_id == 1 && reply.run_id == 2 &&
          !reply.request_id && payload.status_code == protocol::StatusCode::ERROR_QUOTA;
    }
  }
  protocol::StartRunPayload start; start.tier_override = -1; start.guest_payload = {'x'};
  if (!quota || !f.conn.sessions.at(1)->runs.contains(1) || f.conn.sessions.at(1)->runs.contains(2) ||
      f.conn.in_relay_bytes || f.conn.ReadsPaused() ||
      !ReadThroughPressure(f, protocol::BuildStartRunFrame(ControlHeader(5, 2, 11), start)) ||
      f.posts.back().run_id != 11 || f.closes) {
    *detail = "per-run input quota escaped its run or blocked another session"; return false;
  }
  return true;
}
bool RetrySessionContainment(std::string *detail) {
  RouterFixture f; f.early = true;
  f.service->test_now = [] { return std::chrono::steady_clock::time_point{} + std::chrono::milliseconds(1000); };
  f.service->test_post = [&](const std::vector<uint8_t> &bytes) {
    v8host::RunEnvelope env;
    if (!v8host::DecodeRunEnvelope(bytes.data(), bytes.size(), &env)) return router::PostOutcome::kAmbiguous;
    if (env.run_id == 1) return router::PostOutcome::kNotWritten;
    f.posts.push_back(env); return router::PostOutcome::kWritten;
  };
  if (!f.Create() || !f.Start(1)) return false;
  auto *slow = f.worker; DrainLocal(f.conn);
  protocol::StartRunPayload start; start.tier_override = -1; start.guest_payload = {'x'};
  if (!ReadThroughPressure(f, protocol::BuildCreateSessionFrame(ControlHeader(3, 2), LogicalConfig())) ||
      !ReadThroughPressure(f, protocol::BuildStartRunFrame(ControlHeader(4, 2, 11), start)) ||
      slow->retry_deadline == std::chrono::steady_clock::time_point{} || f.conn.ReadsPaused() ||
      f.posts.size() != 1 || f.posts.front().run_id != 11 || f.closes) {
    *detail = "a slow guest's pending retry blocked another session's pipe request"; return false;
  }
  return true;
}
bool PausedDisconnect(std::string *detail) {
  RouterFixture f; f.early = true; PressurePipe pipe;
  if (!f.Create() || !f.Start(1) || !pipe.Open()) return false;
  DrainLocal(f.conn);
  for (size_t i = 0; i < protocol::kMaxControlQueueRequests - 1; ++i)
    if (!f.conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)))) return false;
  f.conn.pipe = pipe.server; f.conn.dispatcher = f.service.get(); f.conn.read_paused = pipe.paused;
  HANDLE done = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!done) return false;
  bool read = true; uint8_t byte; DWORD size;
  std::thread reader([&] { read = f.conn.ReadFrame(&byte, 1, &size, INFINITE); ::SetEvent(done); });
  bool passed = ::WaitForSingleObject(pipe.paused, 5000) == WAIT_OBJECT_0 && !f.conn.active_io;
  ::CloseHandle(pipe.client); pipe.client = INVALID_HANDLE_VALUE;
  passed = passed && ::WaitForSingleObject(done, 5000) == WAIT_OBJECT_0;
  if (!passed) f.conn.Stop();
  reader.join(); ::CloseHandle(done); f.conn.pipe = INVALID_HANDLE_VALUE; f.conn.read_paused = nullptr;
  f.service->Close(f.conn); f.conn.ClearOutput();
  if (!passed || read || !f.conn.CompleteZero() || f.closes != 1 || f.waits != 1) {
    *detail = "disconnect during connection-level pause was not detected and reaped"; return false;
  }
  return true;
}
bool BookkeepingCallbackOverlap(std::string *detail) {
  for (bool terminal : {false, true}) {
    RouterFixture f; f.early = true;
    if (!f.Create() || !f.Start(1) || (terminal && !f.Start(2))) return false;
    DrainLocal(f.conn);
    HANDLE entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!entered || !release) return false;
    f.worker->ledger_publication = [&] { ::SetEvent(entered); ::WaitForSingleObject(release, INFINITE); };
    bool admitted = false;
    std::thread strand([&] {
      admitted = terminal ? f.conn.sessions.at(1)->runs.at(2)->TryTerminal(router::RunState::kCancelled) : f.Start(2);
    });
    bool passed = ::WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0;
    auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
    if (passed) router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
    passed = passed && !f.worker->mailbox_failed && f.conn.out_relay_bytes == 37;
    ::SetEvent(release); strand.join(); f.worker->ledger_publication = nullptr;
    ::CloseHandle(entered); ::CloseHandle(release); f.service->Pump(f.conn);
    size_t relays = 0; protocol::FrameHeader h;
    while (PopFrame(f.conn, &h)) if (h.type == protocol::MessageType::RELAY_FROM_WORKER && h.run_id == 1) ++relays;
    if (!passed || !admitted || relays != 1 || f.conn.sessions.size() != 1 || f.closes ||
        f.worker->mailbox_failed || f.worker->ledger_pins.size() > 5) {
      *detail = terminal ? "terminal bookkeeping killed a healthy callback" : "START admission killed a healthy callback";
      return false;
    }
  }
  return true;
}
bool LedgerHazardChurn(std::string *detail) {
  RouterFixture f; f.early = true;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  HANDLE entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr), release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!entered || !release) return false;
  auto weak = std::weak_ptr(f.conn.sessions.at(1)->runs.at(1)->outbound);
  f.worker->ledger_acquired = [&] { ::SetEvent(entered); ::WaitForSingleObject(release, INFINITE); };
  auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
  std::thread callback([&] { router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size()); });
  bool passed = ::WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0;
  if (passed) {
    f.conn.sessions.at(1)->runs.at(1)->TryTerminal(router::RunState::kFailed);
    f.conn.sessions.at(1)->retired_runs.clear();
    for (uint32_t id = 2; id < 102 && passed; ++id) {
      passed = f.Start(id);
      if (passed) passed = f.conn.sessions.at(1)->runs.at(id)->TryTerminal(router::RunState::kCancelled);
      f.conn.sessions.at(1)->retired_runs.clear(); DrainLocal(f.conn);
      passed = passed && !weak.expired() && f.worker->ledger_pins.size() <= 5;
    }
  }
  ::SetEvent(release); callback.join(); f.worker->ledger_acquired = nullptr;
  ::CloseHandle(entered); ::CloseHandle(release); f.service->Pump(f.conn); DrainLocal(f.conn);
  if (passed) passed = f.Start(102) && weak.expired() && !f.worker->mailbox_failed;
  if (!passed) *detail = "reader hazard lost a retired ledger or accumulated unbounded churn pins";
  return passed;
}
bool OutputLossSticky(std::string *detail) {
  for (auto terminal : {v8host::RunEnvelopeType::kResult, v8host::RunEnvelopeType::kRunError}) {
    RouterFixture f; f.early = true;
    if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    auto ledger = f.conn.sessions.at(1)->runs.at(1)->outbound;
    auto held = f.conn.ChargeOutput(protocol::kMaxQueuedRelayBytesPerRun - 36, ledger);
    auto first = v8host::EncodeRunEnvelope(GuestRelay(0));
    router::Worker::OnMessage(f.worker, sbox_msg_binary, first.data(), first.size());
    bool injected = false, rejected = false;
    f.worker->mailbox_readout = [&] {
      if (injected) return;
      injected = true;
      auto overflow = v8host::EncodeRunEnvelope(GuestRelay(1));
      const size_t tail = f.worker->mailbox_tail;
      router::Worker::OnMessage(f.worker, sbox_msg_binary, overflow.data(), overflow.size());
      held.Reset();
      router::Worker::OnMessage(f.worker, sbox_msg_binary, first.data(), first.size());
      rejected = ledger->failed && f.worker->mailbox_tail == tail;
      v8host::RunEnvelope result; result.type = terminal; result.run_id = 1;
      auto bytes = v8host::EncodeRunEnvelope(result);
      router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
    };
    f.service->Pump(f.conn); f.worker->mailbox_readout = nullptr;
    size_t errors = 0; std::vector<uint8_t> output;
    while (f.conn.TakeOutput(&output)) {
      f.conn.CompleteOutput(output.size()); protocol::FrameHeader h; const uint8_t *body; size_t size;
      if (protocol::DecodeAndValidateFrame(output.data(), output.size(), &h, &body, &size) != protocol::DecodeStatus::kOk)
        return false;
      if (h.type != protocol::MessageType::RUN_ERROR || h.run_id != 1 || h.request_id) return false;
      protocol::ErrorPayload error;
      if (!protocol::DecodeErrorPayload(body, size, &error) || error.status_code != protocol::StatusCode::ERROR_QUOTA)
        return false;
      ++errors;
    }
    if (!injected || !rejected || errors != 1 || ledger->bytes || f.worker->mailbox_failed || f.closes ||
        f.conn.sessions.at(1)->runs.contains(1) || !f.conn.sessions.at(1)->runs.contains(2) ||
        f.worker->engine_busy_run_id != 2) {
      *detail = "same-drain loss allowed success, post-gap delivery, or stranded the busy cursor"; return false;
    }
  }
  return true;
}
bool DiscardIntakeOrdering(std::string *detail) {
  RouterFixture f; f.early = true;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  HANDLE entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr), release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!entered || !release) return false;
  f.worker->intake_entered = [&] { ::SetEvent(entered); ::WaitForSingleObject(release, INFINITE); };
  auto *worker = f.worker;
  auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
  std::thread callback([&] { router::Worker::OnMessage(worker, sbox_msg_binary, encoded.data(), encoded.size()); });
  bool passed = ::WaitForSingleObject(entered, 5000) == WAIT_OBJECT_0;
  const size_t tail = worker->mailbox_tail;
  worker->DiscardMailbox();
  ::SetEvent(release); callback.join(); worker->intake_entered = nullptr;
  ::CloseHandle(entered); ::CloseHandle(release);
  if (!passed || worker->mailbox_tail != tail || f.conn.out_relay_bytes || worker->intake_active) {
    *detail = "callback published a late credit after mailbox discard"; return false;
  }
  return true;
}
bool TerminalBeforeFallback(std::string *detail) {
  RouterFixture f; f.early = true;
  int64_t ticks = 1000;
  f.service->test_now = [&] { return std::chrono::steady_clock::time_point{} + std::chrono::milliseconds(ticks); };
  if (!f.Create() || !f.Start(1) || !f.Start(2) ||
      !LocalRoute(*f.service, f.conn, protocol::BuildCancelRunFrame(ControlHeader(4, 1, 1)))) return false;
  DrainLocal(f.conn);
  ticks = 5999;
  v8host::RunEnvelope result; result.type = v8host::RunEnvelopeType::kResult; result.run_id = 1;
  result.disposition = v8host::RunEnvelopeDisposition::kCancelled;
  auto bytes = v8host::EncodeRunEnvelope(result);
  router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
  ticks = 6000; f.service->Pump(f.conn);
  protocol::FrameHeader h;
  if (f.closes || f.conn.sessions.empty() || f.worker->cancel_deadline != std::chrono::steady_clock::time_point{} ||
      f.worker->engine_busy_run_id != 2 || !PopFrame(f.conn, &h) || h.type != protocol::MessageType::RESULT ||
      h.run_id != 1 || PopFrame(f.conn, &h)) {
    *detail = "already-published worker terminal lost to a later cancel fallback pump"; return false;
  }
  return true;
}
bool FinalReplyMailbox(std::string *detail) {
  RouterFixture f; f.early = true; PressurePipe pipe;
  if (!f.Create() || !f.Start(1) || !pipe.Open()) return false;
  DrainLocal(f.conn);
  auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
  router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
  // Keep both relay and control credits in unpumped worker mailboxes.
  const uint8_t startup[] = {1, 0, 0, 0};
  router::Worker::OnMessage(f.worker, sbox_msg_lifecycle, startup, sizeof(startup));
  auto h = ControlHeader(19, 0, 3); h.type = static_cast<protocol::MessageType>(0xffff);
  h.flags = protocol::kFlagMustUnderstand;
  std::vector<uint8_t> unknown; protocol::EncodeHeader(h, unknown);
  if (LocalRoute(*f.service, f.conn, unknown) || f.conn.state != router::ConnState::kClosing ||
      f.conn.out_control_requests != 2 || !f.conn.out_relay_bytes) return false;
  f.conn.pipe = pipe.server;
  if (!f.conn.StartWriter()) return false;
  const bool preserved = f.conn.DrainOutput(5000);
  f.conn.Stop(); f.conn.JoinWriter(); f.service->Close(f.conn); f.conn.ClearOutput();
  if (!preserved) ::DisconnectNamedPipe(pipe.server);
  ::CloseHandle(pipe.server); pipe.server = INVALID_HANDLE_VALUE; f.conn.pipe = INVALID_HANDLE_VALUE;
  std::array<uint8_t, protocol::kMaxFrameSize> bytes; DWORD size = 0;
  protocol::FrameHeader reply; const uint8_t *body; size_t body_size; protocol::ErrorPayload error;
  if (!preserved || !::ReadFile(pipe.client, bytes.data(), static_cast<DWORD>(bytes.size()), &size, nullptr) ||
      protocol::DecodeAndValidateFrame(bytes.data(), size, &reply, &body, &body_size) != protocol::DecodeStatus::kOk ||
      reply.type != protocol::MessageType::ERROR || reply.request_id != 19 ||
      !protocol::DecodeErrorPayload(body, body_size, &error) ||
      error.status_code != protocol::StatusCode::ERROR_UNSUPPORTED_MESSAGE || !f.conn.CompleteZero()) {
    *detail = "mailbox credits withheld the mandatory error or close discarded it"; return false;
  }
  return true;
}
bool WorkerMailboxOverflow(std::string *detail) {
  for (int delta : {-1, 0, 1}) {
    RouterFixture f; f.early = true;
    if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    size_t bytes = protocol::kMaxQueuedRelayBytesPerRun + delta, n = 0;
    while (bytes) {
      const size_t part = (std::min)(bytes, size_t(protocol::kMaxFramePayload));
      auto encoded = v8host::EncodeRunEnvelope(GuestRelay(part - 16, ++n % 2 ? 1 : 2));
      router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
      bytes -= part;
    }
    if (f.worker->mailbox_failed != (delta > 0) ||
        f.worker->byte_tail - f.worker->byte_head > protocol::kMaxQueuedRelayBytesPerRun) return false;
    f.service->Pump(f.conn);
    if (f.conn.sessions.empty() != (delta > 0)) return false;
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (!f.conn.CompleteZero()) return false;
  }
  for (bool malformed : {false, true}) {
    RouterFixture f; f.early = true;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1)) return false;
    DrainLocal(f.conn);
    auto *worker = f.worker;
    auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1));
    if (!malformed) for (size_t i = 0; i < worker->mailbox.size(); ++i)
      router::Worker::OnMessage(worker, sbox_msg_binary, encoded.data(), encoded.size());
    router::Worker::OnMessage(worker, sbox_msg_binary, malformed ? nullptr : encoded.data(), encoded.size());
    const bool retained_failure = worker->mailbox_failed;
    f.service->Pump(f.conn);
    if (!retained_failure || !f.conn.sessions.empty() || ::WaitForSingleObject(f.wait_entered, 5000) != WAIT_OBJECT_0)
      return false;
    const size_t tail = worker->mailbox_tail;
    router::Worker::OnMessage(worker, sbox_msg_binary, encoded.data(), encoded.size());
    if (worker->mailbox_tail != tail || f.conn.out_relay_bytes || !PopWorkerExit(f.conn)) return false;
    ::SetEvent(f.wait_release); f.service->Close(f.conn);
    if (!f.conn.CompleteZero() || f.waits != 1 || f.closes != 1 || f.post_after_close || f.close_before_removal) return false;
  }
  RouterFixture f; f.early = true;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  f.worker->byte_head = SIZE_MAX - 10; f.worker->byte_tail = SIZE_MAX - 10;
  for (uint8_t i = 0; i < 64; ++i) {
    auto encoded = v8host::EncodeRunEnvelope(GuestRelay(1)); encoded.back() = i;
    router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
  }
  f.service->Pump(f.conn);
  for (uint8_t i = 0; i < 64; ++i) {
    std::vector<uint8_t> frame;
    if (!f.conn.TakeOutput(&frame) || frame.back() != i) { *detail = "64-fact burst or byte-ring wrap lost FIFO"; return false; }
    f.conn.CompleteOutput(frame.size());
  }
  return !f.worker->mailbox_failed && !f.conn.out_relay_bytes && f.worker->byte_head == f.worker->byte_tail;
}
bool IdExhaustion(std::string *detail) {
  std::atomic<uint32_t> next{UINT32_MAX - 2};
  std::array<uint32_t, 4> ids{}; std::array<std::thread, 4> contenders;
  HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!release) return false;
  for (size_t i = 0; i < contenders.size(); ++i) contenders[i] = std::thread([&, i] {
    ::WaitForSingleObject(release, INFINITE); ids[i] = router::AllocateId(next);
  });
  ::SetEvent(release); for (auto &thread : contenders) thread.join(); ::CloseHandle(release);
  std::sort(ids.begin(), ids.end());
  if (ids != std::array<uint32_t, 4>{0, 0, UINT32_MAX - 2, UINT32_MAX - 1} || next != UINT32_MAX || router::AllocateId(next)) {
    *detail = "allocator wrapped or reused exhausted id"; return false;
  }
  for (int field = 0; field < 3; ++field) {
    router::Connection conn; OpenLocal(conn); router::Router service(BrokerMode::kDedicated);
    auto h = ControlHeader(field == 0 ? UINT32_MAX : 1, field == 1 ? UINT32_MAX : 1);
    auto frame = protocol::BuildCreateSessionFrame(h, LogicalConfig());
    if (field == 2) { h = ControlHeader(1, 1, UINT32_MAX); frame = protocol::BuildCancelRunFrame(h); }
    if (LocalRoute(service, conn, frame) || ::WaitForSingleObject(conn.stop, 0) != WAIT_OBJECT_0) return false;
    service.Close(conn); if (!conn.CompleteZero()) return false;
  }
  return true;
}
bool FillInbound(RouterFixture &f, uint32_t session, size_t bytes) {
  while (bytes) {
    const size_t part = (std::min)(bytes, size_t(protocol::kMaxFramePayload));
    if (part < 16) return false;
    auto h = ControlHeader(0, session, 1); h.type = protocol::MessageType::RELAY_TO_WORKER;
    std::vector<uint8_t> payload(part - 16, 7);
    if (!LocalRoute(*f.service, f.conn, protocol::BuildRelayFrame(h, sbox_msg_binary, payload.data(), payload.size())))
      return false;
    bytes -= part;
  }
  return true;
}
bool FillOutbound(RouterFixture &f, router::Worker *worker, size_t bytes) {
  while (bytes) {
    const size_t part = (std::min)(bytes, size_t(protocol::kMaxFramePayload + 20));
    if (part < 36) return false;
    auto encoded = v8host::EncodeRunEnvelope(GuestRelay(part - 36));
    router::Worker::OnMessage(worker, sbox_msg_binary, encoded.data(), encoded.size());
    f.service->Pump(f.conn);
    bytes -= part;
  }
  return true;
}
bool RelayRunBoundary(std::string *detail) {
  {
    RouterFixture f; f.early = true;
    if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    for (uint32_t id : {1u, 2u}) {
      auto credit = f.conn.ChargeOutput(protocol::kMaxQueuedRelayBytesPerRun + 1,
          f.conn.sessions.at(1)->runs.at(id)->outbound);
      if (credit.conn) return false;
    }
    f.service->test_post = [](const std::vector<uint8_t> &) { return router::PostOutcome::kAmbiguous; };
    f.service->Pump(f.conn);
    if (!f.conn.sessions.empty()) return false;
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (!f.conn.CompleteZero() || f.closes != 1 || f.waits != 1) {
      *detail = "simultaneous run overflows followed removed session after ambiguous CANCEL"; return false;
    }
  }
  for (bool outbound : {false, true}) for (int delta : {-1, 0, 1}) {
    RouterFixture f; f.early = outbound;
    if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    auto ledger = f.conn.sessions.at(1)->runs.at(1)->outbound;
    const size_t target = protocol::kMaxQueuedRelayBytesPerRun + delta;
    if (!(outbound ? FillOutbound(f, f.worker, target) : FillInbound(f, 1, target))) return false;
    const bool live = f.conn.sessions.at(1)->runs.contains(1);
    const size_t charged = outbound ? f.conn.out_relay_bytes.load() : f.conn.in_relay_bytes;
    if (live != (delta <= 0) || !f.conn.sessions.at(1)->runs.contains(2) ||
        ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0 || charged > protocol::kMaxQueuedRelayBytesPerRun ||
        (delta <= 0 && charged != target)) {
      *detail = "run quota direction/boundary/containment"; return false;
    }
    if (delta > 0) {
      bool quota = false;
      protocol::FrameHeader h; std::vector<uint8_t> frame;
      while (f.conn.TakeOutput(&frame)) {
        f.conn.CompleteOutput(frame.size());
        const uint8_t *body; size_t size;
        if (protocol::DecodeAndValidateFrame(frame.data(), frame.size(), &h, &body, &size) != protocol::DecodeStatus::kOk)
          return false;
        if (h.type == protocol::MessageType::RUN_ERROR) {
          protocol::ErrorPayload error;
          quota = protocol::DecodeErrorPayload(body, size, &error) && h.request_id == 0 && h.run_id == 1 &&
              error.status_code == protocol::StatusCode::ERROR_QUOTA;
        }
      }
      if (!quota || (outbound && f.worker->engine_busy_run_id != 1)) return false;
    }
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (ledger->bytes || !f.conn.CompleteZero()) return false;
  }
  return true;
}
bool RelayConnectionBoundary(std::string *detail) {
  for (bool outbound : {false, true}) for (int delta : {-1, 0, 1}) {
    RouterFixture f; f.early = outbound;
    std::vector<router::Worker *> workers;
    uint32_t request = 0;
    for (uint32_t id = 1; id <= 17; ++id) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(++request, id), LogicalConfig())))
        return false;
      protocol::StartRunPayload start; start.tier_override = -1; start.guest_payload = {'x'};
      if (!LocalRoute(*f.service, f.conn, protocol::BuildStartRunFrame(ControlHeader(++request, id, 1), start))) return false;
      workers.push_back(f.worker);
    }
    DrainLocal(f.conn);
    for (uint32_t id = 1; id <= 16; ++id) {
      const size_t bytes = protocol::kMaxQueuedRelayBytesPerRun - (id == 16 ? 100 : 0);
      if (!(outbound ? FillOutbound(f, workers[id - 1], bytes) : FillInbound(f, id, bytes))) return false;
    }
    const bool accepted = outbound ? FillOutbound(f, workers[16], 100 + delta) : FillInbound(f, 17, 100 + delta);
    const size_t charged = outbound ? f.conn.out_relay_bytes.load() : f.conn.in_relay_bytes;
    if (!outbound && delta > 0) {
      std::vector<uint8_t> frame; protocol::FrameHeader h;
      const uint8_t *body; size_t size; protocol::ErrorPayload error;
      if (!f.conn.TakeOutput(&frame)) { *detail = "aggregate rejection missing ERROR_QUOTA"; return false; }
      f.conn.CompleteOutput(frame.size());
      if (protocol::DecodeAndValidateFrame(frame.data(), frame.size(), &h, &body, &size) != protocol::DecodeStatus::kOk ||
          h.type != protocol::MessageType::ERROR || h.conn_id != f.conn.conn_id ||
          h.session_id != 17 || h.run_id != 1 || h.request_id != 0 ||
          !protocol::DecodeErrorPayload(body, size, &error) || error.status_code != protocol::StatusCode::ERROR_QUOTA ||
          f.conn.in_relay_bytes != protocol::kMaxQueuedRelayBytesPerConnection - 100) {
        *detail = "aggregate rejection must enqueue addressed ERROR_QUOTA without input credit"; return false;
      }
    }
    if ((!outbound && accepted != (delta <= 0)) ||
        (::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0) != (outbound && delta > 0) ||
        (!outbound && (f.conn.state == router::ConnState::kClosing) != (delta > 0)) ||
        charged > protocol::kMaxQueuedRelayBytesPerConnection ||
        (delta <= 0 && charged != protocol::kMaxQueuedRelayBytesPerConnection + delta)) {
      *detail = "connection quota boundary did not contain entire connection"; return false;
    }
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (!f.conn.CompleteZero() || f.closes != 17 || f.waits != 17 || f.post_after_close || f.close_before_removal)
      return false;
  }
  return true;
}
bool InboundErrorDrain(std::string *detail) {
  for (int path = 0; path < 4; ++path) {
    RouterFixture f; PressurePipe pipe;
    uint32_t request = 0;
    for (uint32_t id = 1; id <= 17; ++id) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCreateSessionFrame(ControlHeader(++request, id), LogicalConfig()))) return false;
      protocol::StartRunPayload start; start.tier_override = -1; start.guest_payload = {'x'};
      if (!LocalRoute(*f.service, f.conn, protocol::BuildStartRunFrame(ControlHeader(++request, id, 1), start))) return false;
    }
    DrainLocal(f.conn);
    for (uint32_t id = 1; id <= 16; ++id)
      if (!FillInbound(f, id, protocol::kMaxQueuedRelayBytesPerRun - (id == 16 ? 100 : 0))) return false;
    if (!pipe.Open(true)) return false;
    HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!release || !pending) return false;
    f.conn.pipe = pipe.server; f.conn.writer_release = release; f.conn.write_pending = pending;
    bool passed = f.conn.StartWriter();
    // Hold the sole writer until the rejection and preceding output are queued.
    if (path == 1) passed &= f.conn.Enqueue(std::vector<uint8_t>(protocol::kMaxFrameSize, 0));
    else if (path == 3) {
      for (size_t n = 0; n < protocol::kMaxControlQueueRequests; ++n)
        passed &= f.conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)));
    } else passed &= f.conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)));
    passed &= !FillInbound(f, 17, 101) && f.conn.in_relay_bytes == protocol::kMaxQueuedRelayBytesPerConnection - 100;
    passed &= path == 3 ? ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0 :
        f.conn.state == router::ConnState::kClosing && ::WaitForSingleObject(f.conn.stop, 0) == WAIT_TIMEOUT;
    if (path == 2) { ::CloseHandle(pipe.client); pipe.client = INVALID_HANDLE_VALUE; }
    ::SetEvent(release);
    if (path == 0) {
      std::array<uint8_t, protocol::kMaxFrameSize> frame;
      for (int n = 0; n < 2; ++n) {
        DWORD count = 0; protocol::FrameHeader h; const uint8_t *body; size_t size; protocol::ErrorPayload error;
        passed &= PressureTransfer(pipe.client, false, frame.data(), static_cast<DWORD>(frame.size()), &count) &&
            protocol::DecodeAndValidateFrame(frame.data(), count, &h, &body, &size) == protocol::DecodeStatus::kOk;
        if (n == 0) passed &= h.type == protocol::MessageType::ACK;
        else passed &= h.type == protocol::MessageType::ERROR && h.conn_id == 1 && h.session_id == 17 &&
            h.run_id == 1 && h.request_id == 0 && protocol::DecodeErrorPayload(body, size, &error) &&
            error.status_code == protocol::StatusCode::ERROR_QUOTA;
      }
      passed &= f.conn.DrainOutput(2000);
    } else if (path == 1) {
      passed &= ::WaitForSingleObject(pending, 5000) == WAIT_OBJECT_0 && !f.conn.DrainOutput(30);
    } else if (path == 2) passed &= ::WaitForSingleObject(f.conn.stop, 5000) == WAIT_OBJECT_0;
    const ULONGLONG begin = ::GetTickCount64();
    f.conn.Stop(); f.conn.JoinWriter(); f.service->Close(f.conn); f.conn.ClearOutput();
    passed &= ::GetTickCount64() - begin < 5000;
    ::CloseHandle(pipe.server); pipe.server = INVALID_HANDLE_VALUE; f.conn.pipe = INVALID_HANDLE_VALUE;
    if (path == 0) {
      uint8_t byte; DWORD count;
      passed &= !PressureTransfer(pipe.client, false, &byte, 1, &count);
      passed &= !::PeekNamedPipe(pipe.client, nullptr, 0, nullptr, nullptr, nullptr) &&
          ::GetLastError() == ERROR_BROKEN_PIPE;
    }
    f.conn.writer_release = f.conn.write_pending = nullptr;
    ::CloseHandle(release); ::CloseHandle(pending);
    if (!passed || !f.conn.CompleteZero() || f.closes != 17 || f.waits != 17 || !f.posts.empty() || f.spawns != 17 ||
        f.conn.active_io || f.conn.writers_started != 1 || f.conn.writers_joined != 1 ||
        f.post_after_close || f.close_before_removal) {
      *detail = "aggregate error drain/failed enqueue/broken or nonreading peer path=" + std::to_string(path); return false;
    }
  }
  return true;
}
bool ControlBoundary(std::string *detail) {
  for (bool bytes : {false, true}) for (int delta : {-1, 0, 1}) {
    router::Connection conn;
    const size_t target = (bytes ? protocol::kMaxControlQueueBytes : protocol::kMaxControlQueueRequests) + delta;
    size_t added = 0; bool accepted = true;
    while (added < target) {
      const size_t part = bytes ? (std::min)(size_t(protocol::kMaxFrameSize), target - added) : 1;
      accepted = conn.Enqueue(std::vector<uint8_t>(bytes ? part : protocol::kFrameHeaderSize));
      if (!accepted) break;
      added += part;
    }
    if (accepted != (delta <= 0) || (delta <= 0 && added != target) ||
        (::WaitForSingleObject(conn.stop, 0) == WAIT_OBJECT_0) != (delta > 0)) {
      *detail = "control byte/request boundary"; return false;
    }
    conn.ClearOutput();
    if (!conn.CompleteZero()) return false;
  }
  return true;
}
bool CreditAllPaths(std::string *detail) {
  for (int path = 0; path < 5; ++path) {
    RouterFixture f;
    if (!f.Create() || !f.Start(1) || !f.Relay(1, 10)) return false;
    auto ledger = f.conn.sessions.at(1)->runs.at(1)->outbound;
    if (f.conn.in_relay_bytes != 26) return false;
    if (path == 0) { f.Phase(1); f.Phase(2); }
    else if (path == 1) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1)))) return false;
    } else if (path == 2) {
      f.conn.sessions.at(1)->runs.at(1)->TryTerminal(router::RunState::kFailed);
    } else if (path == 3) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(9)))) return false;
    } else f.service->Close(f.conn);
    if (f.conn.in_relay_bytes) { *detail = "inbound credit leaked on path " + std::to_string(path); return false; }
    DrainLocal(f.conn);
    if (path == 4) continue;
    auto credit = f.conn.ChargeOutput(100, ledger);
    if (!credit.conn || !f.conn.Enqueue(std::vector<uint8_t>(100), std::move(credit)) ||
        ledger->bytes != 100 || f.conn.out_relay_bytes != 100 || f.conn.out_control_requests) return false;
    std::vector<uint8_t> frame;
    if (!f.conn.TakeOutput(&frame) || ledger->bytes != 100) return false;
    if (path % 2) f.conn.ClearOutput(); else f.conn.CompleteOutput(frame.size());
    f.conn.CompleteOutput(frame.size());
    if (ledger->bytes || f.conn.out_relay_bytes || f.conn.out_control_bytes || f.conn.out_control_requests)
      return false;
  }
  for (int path = 0; path < 5; ++path) {
    RouterFixture f; f.early = true;
    if (!f.Create() || !f.Start(1) || !f.Start(2)) return false;
    DrainLocal(f.conn);
    auto ledger = f.conn.sessions.at(1)->runs.at(1)->outbound;
    const uint32_t id = path == 1 ? 2 : 1;
    auto other = f.conn.sessions.at(1)->runs.at(id)->outbound;
    auto encoded = v8host::EncodeRunEnvelope(GuestRelay(10, id));
    router::Worker::OnMessage(f.worker, sbox_msg_binary, encoded.data(), encoded.size());
    if (other->bytes != 46 || f.conn.out_relay_bytes != 46) return false;
    if (path <= 2) {
      if (path == 2) f.Terminal(1); else f.service->Pump(f.conn);
      if ((path == 1 && (other->bytes || f.conn.out_relay_bytes)) || (path != 1 && ledger->bytes != 46)) return false;
      DrainLocal(f.conn);
    } else if (path == 3) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(9)))) return false;
    } else f.service->Close(f.conn);
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (other->bytes || ledger->bytes || !f.conn.CompleteZero()) {
      *detail = "mailbox transfer/drop/terminal/close/disconnect credit leaked"; return false;
    }
  }
  return true;
}
bool RetryFifoCredits(std::string *detail) {
  for (int terminal = 0; terminal < 5; ++terminal) {
    RouterFixture f; f.early = true;
    auto now = std::chrono::steady_clock::time_point{} + std::chrono::seconds(1);
    f.service->test_now = [&] { return now; };
    if (!f.Create() || !f.Start(1)) return false;
    DrainLocal(f.conn);
    unsigned attempts = 0; bool writable = false;
    f.service->test_post = [&](const std::vector<uint8_t> &bytes) {
      ++attempts;
      if (!writable) return router::PostOutcome::kNotWritten;
      v8host::RunEnvelope env;
      if (!v8host::DecodeRunEnvelope(bytes.data(), bytes.size(), &env)) return router::PostOutcome::kAmbiguous;
      f.posts.push_back(std::move(env)); return router::PostOutcome::kWritten;
    };
    if (!f.Relay(1, 1, 7) || !f.Relay(1, 2, 8) || attempts != 1 || f.conn.in_relay_bytes != 35) return false;
    if (terminal == 0) {
      now += std::chrono::milliseconds(9); writable = true; f.service->Pump(f.conn);
      if (attempts != 1 || f.conn.in_relay_bytes != 35) return false;
      now += std::chrono::milliseconds(1); f.service->Pump(f.conn); f.service->Pump(f.conn);
      if (attempts != 3 || f.posts.size() != 3 || f.posts[1].payload != std::vector<uint8_t>{7} ||
          f.posts[2].payload != std::vector<uint8_t>({8, 8})) return false;
    } else if (terminal == 1) f.Terminal(1);
    else if (terminal == 2) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1))) ||
          attempts != 2 || f.worker->pending_cancel_id != 1 || f.conn.in_relay_bytes) return false;
      now += std::chrono::milliseconds(10); writable = true; f.service->Pump(f.conn); f.service->Pump(f.conn);
      if (attempts != 3 || f.posts.size() != 2 || f.posts.back().type != v8host::RunEnvelopeType::kCancel) return false;
      f.Terminal(1);
    } else if (terminal == 3) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(9)))) return false;
    } else f.service->Close(f.conn);
    const unsigned before = attempts;
    now += std::chrono::seconds(20); f.service->Pump(f.conn);
    if (attempts != before || f.conn.in_relay_bytes || f.service->WakeDelay(f.conn, INFINITE) != INFINITE) {
      *detail = "retry head credit/FIFO/terminal cancellation"; return false;
    }
    f.service->Close(f.conn); f.conn.ClearOutput();
    if (!f.conn.CompleteZero() || f.post_after_close || f.closes != 1 || f.waits != 1) return false;
  }
  return true;
}
bool RetryExhaustion(std::string *detail) {
  for (int mode = 0; mode < 5; ++mode) {
    RouterFixture f;
    auto now = std::chrono::steady_clock::time_point{} + std::chrono::seconds(1);
    f.service->test_now = [&] { return now; };
    unsigned attempts = 0;
    f.service->test_post = [&](const std::vector<uint8_t> &bytes) {
      ++attempts;
      if (mode == 1 && attempts == 4) {
        v8host::RunEnvelope env;
        if (!v8host::DecodeRunEnvelope(bytes.data(), bytes.size(), &env)) return router::PostOutcome::kAmbiguous;
        f.posts.push_back(std::move(env));
        return router::PostOutcome::kWritten;
      }
      return mode == 2 ? router::PostOutcome::kAmbiguous : router::PostOutcome::kNotWritten;
    };
    if (!f.Create() || !f.Start(1)) return false;
    f.Phase(1); f.Phase(2);
    if (attempts != 1 || (mode != 2 && f.worker->engine_busy_run_id)) return false;
    if (mode == 3) {
      if (!LocalRoute(*f.service, f.conn, protocol::BuildCancelRunFrame(ControlHeader(9, 1, 1)))) return false;
    } else if (mode == 4) f.service->Close(f.conn);
    if (mode >= 2) {
      now += std::chrono::seconds(20); f.service->Pump(f.conn);
      if (attempts != 1) return false;
    } else {
      for (unsigned retry = 0; retry < (mode == 1 ? 3u : 16u); ++retry) {
        const unsigned delay = (std::min)(100u, 10u << (std::min)(retry, 4u));
        if (f.service->WakeDelay(f.conn, INFINITE) != delay) return false;
        now += std::chrono::milliseconds(delay - 1); f.service->Pump(f.conn);
        if (attempts != retry + 1) { *detail = "early retry"; return false; }
        now += std::chrono::milliseconds(1); f.service->Pump(f.conn);
        if (attempts != retry + 2) return false;
      }
      now += std::chrono::seconds(1); f.service->Pump(f.conn);
      if (mode == 1 && (f.posts.size() != 1 || f.worker->engine_busy_run_id != 1 || attempts != 4)) return false;
    }
    if (mode == 0 || mode == 2) {
      if (!f.conn.sessions.empty()) return false;
      f.service->Close(f.conn);
      if (f.closes != 1 || f.waits != 1 || f.post_after_close || f.close_before_removal) return false;
    }
    if (f.service->WakeDelay(f.conn, INFINITE) != INFINITE) return false;
  }
  return true;
}
bool DefinitePostFailure(std::string *detail) { return RetryExhaustion(detail) && RetryFifoCredits(detail); }
bool SpawnFailure(std::string *detail) {
  for (int mode = 0; mode < 3; ++mode) {
    const bool missing_image = mode == 0;
    RouterFixture f;
    f.fail_spawn = true;
    f.early = mode == 2;
    for (uint32_t id = 1; id <= 80; ++id) {
      if (!LocalRoute(*f.service, f.conn,
          protocol::BuildCreateSessionFrame(ControlHeader(id * 2, id), LogicalConfig()))) return false;
      DrainLocal(f.conn);
      protocol::StartRunPayload start;
      start.tier_override = -1;
      start.guest_payload = {'x'};
      if (missing_image) {
        start.has_engine_override = true;
        start.engine_filename = "missing-worker-engine.dll";
      }
      if (!LocalRoute(*f.service, f.conn,
          protocol::BuildStartRunFrame(ControlHeader(id * 2 + 1, id, 1), start))) return false;
      protocol::FrameHeader h;
      protocol::StatusCode code;
      if (!PopFrame(f.conn, &h) || h.type != protocol::MessageType::ACK || !PopFrame(f.conn, &h, &code) ||
          h.type != protocol::MessageType::RUN_ERROR || code != protocol::StatusCode::ERROR_INTERNAL ||
          !f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || f.closes || f.waits || !f.posts.empty() ||
          !PopWorkerExit(f.conn, id) || ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0 ||
          f.spawns != (missing_image ? 0 : id) || (mode == 2 && !f.before_publication)) {
        *detail = "failed spawn retained storage or exhausted connection at " + std::to_string(id);
        return false;
      }
    }
  }
  return true;
}
bool CloseDuringPublication(std::string *detail) {
  for (bool stop_first : {false, true}) {
    RouterFixture f;
    f.early = true;
    f.stop_during_spawn = stop_first;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1) || !f.before_publication)
      return false;
    if (!stop_first && !LocalRoute(*f.service, f.conn, protocol::BuildCloseSessionFrame(ControlHeader(9))))
      return false;
    if (::WaitForSingleObject(f.wait_entered, 3000) != WAIT_OBJECT_0 || !f.conn.sessions.empty() || f.closes != 1 ||
        (stop_first && !f.posts.empty()))
      return false;
    f.service->Pump(f.conn);
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (f.waits != 1 || f.post_after_close || f.close_before_removal || !f.conn.retired_sessions.empty()) {
      *detail = "close/publication ownership ordering";
      return false;
    }
  }
  return true;
}
bool MailboxReadout(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1))
    return false;
  f.Phase(1); f.Phase(2);
  DrainLocal(f.conn);
  HANDLE entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE delivered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!entered || !delivered) {
    if (entered) ::CloseHandle(entered);
    if (delivered) ::CloseHandle(delivered);
    return false;
  }
  // Put the counters at wrap to cover unsigned occupancy and slot reuse too.
  f.worker->mailbox_head = SIZE_MAX;
  f.worker->mailbox_tail = SIZE_MAX;
  auto emit = [&](uint8_t byte) {
    auto env = GuestRelay(1);
    env.payload[0] = byte;
    auto bytes = v8host::EncodeRunEnvelope(env);
    router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
  };
  emit(7);
  bool barrier_ok = false, first = true;
  f.worker->mailbox_readout = [&] {
    if (!first) return;
    first = false;
    ::SetEvent(entered);
    barrier_ok = ::WaitForSingleObject(delivered, 3000) == WAIT_OBJECT_0;
  };
  std::thread producer([&] {
    if (::WaitForSingleObject(entered, 3000) == WAIT_OBJECT_0)
      emit(8);
    ::SetEvent(delivered);
  });
  f.service->Pump(f.conn);
  producer.join();
  ::CloseHandle(entered); ::CloseHandle(delivered);
  if (!barrier_ok || f.conn.sessions.empty() || f.closes) {
    *detail = "callback during read-out closed healthy session";
    return false;
  }
  f.worker->mailbox_readout = {};
  for (uint8_t expected : {7, 8}) {
    std::vector<uint8_t> bytes;
    protocol::FrameHeader h;
    const uint8_t *payload, *body;
    size_t size, body_size;
    int32_t kind;
    if (!f.conn.TakeOutput(&bytes)) return false;
    f.conn.CompleteOutput(bytes.size());
    if (protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &h, &payload, &size) != protocol::DecodeStatus::kOk ||
        h.type != protocol::MessageType::RELAY_FROM_WORKER || h.run_id != 1 ||
        !protocol::DecodeRelayPayload(payload, size, &kind, &body, &body_size) ||
        kind != sbox_msg_binary || body_size != 1 || body[0] != expected) {
      *detail = "callback read-out FIFO lost or duplicated";
      return false;
    }
  }
  return f.conn.out_queue.empty() && !f.worker->mailbox_failed &&
      f.worker->mailbox_head == f.worker->mailbox_tail;
}
bool MailboxFailureSticky(std::string *detail) {
  for (bool oversize : {false, true}) {
    RouterFixture f;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1))
      return false;
    f.Phase(1); f.Phase(2);
    if (!f.Start(2) || !f.Relay(2, 1, 9)) return false;
    DrainLocal(f.conn);
    auto *worker = f.worker;
    auto *run = worker->session->runs.at(1).get();
    auto emit = [&](uint8_t byte) {
      auto env = GuestRelay(1);
      env.payload[0] = byte;
      auto bytes = v8host::EncodeRunEnvelope(env);
      router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
    };
    auto later = [&] {
      emit(17);
      v8host::RunEnvelope env;
      env.type = v8host::RunEnvelopeType::kResult;
      env.run_id = 1;
      auto bytes = v8host::EncodeRunEnvelope(env);
      router::Worker::OnMessage(worker, sbox_msg_binary, bytes.data(), bytes.size());
    };
    for (size_t i = 0; i < (oversize ? 1 : worker->mailbox.size()); ++i) emit(static_cast<uint8_t>(i));
    const size_t published = worker->mailbox_tail.load();
    unsigned readouts = 0;
    worker->mailbox_readout = [&] {
      if (++readouts == 1) {
        if (oversize) {
          const uint8_t byte = 0;
          router::Worker::OnMessage(worker, sbox_msg_binary, &byte, protocol::kMaxFramePayload + 1);
          later();
        } else {
          emit(16);  // The copied slot has not been released: this must drop.
        }
      } else if (readouts == 2) {
        later();  // A slot is free; a non-sticky producer would publish again.
      }
    };
    f.service->Pump(f.conn);
    const bool closed_in_pump = f.conn.sessions.empty() && f.worker->close_called;
    if (!closed_in_pump || ::WaitForSingleObject(f.wait_entered, 3000) != WAIT_OBJECT_0) {
      *detail = "mailbox drop did not fail closed in the same Pump";
      return false;
    }
    // Hold the join boundary so callbacks can arrive after a slot becomes free.
    const size_t tail = worker->mailbox_tail.load();
    later();
    const bool rejected = worker->mailbox_failed && worker->mailbox_tail == published && tail == published &&
        worker->mailbox_tail - worker->mailbox_head < worker->mailbox.size() && readouts == 1 &&
        run->state == router::RunState::kWorkerExited && worker->session->runs.empty() &&
        PopWorkerExit(f.conn) && f.posts.size() == 1;
    worker->mailbox_readout = {};
    ::SetEvent(f.wait_release);
    f.service->Close(f.conn);
    if (!rejected || f.closes != 1 || f.waits != 1 || f.close_before_removal || f.post_after_close ||
        !f.conn.retired_sessions.empty()) {
      *detail = "post-drop fact/RESULT delivered, successor dispatched, or cleanup ownership lost";
      return false;
    }
  }
  return true;
}
bool MailboxBoundary(std::string *detail) {
  for (int mode = 0; mode < 5; ++mode) {
    if (mode == 2) {
      if (!MailboxReadout(detail)) return false;
      continue;
    }
    RouterFixture f;
    if (!f.Create() || !f.Start(1))
      return false;
    DrainLocal(f.conn);
    const uint8_t phase[] = {1,0,0,0};
    if (mode == 3)
      router::Worker::OnMessage(f.worker, sbox_msg_binary, phase, protocol::kMaxFramePayload + 1);
    else if (mode == 4)
      router::Worker::OnMessage(f.worker, sbox_msg_binary, nullptr, 1);
    else
      for (size_t i = 0; i < (mode == 0 ? f.worker->mailbox.size() : f.worker->mailbox.size() + 1); ++i)
        router::Worker::OnMessage(f.worker, sbox_msg_lifecycle, phase, 4);
    f.service->Pump(f.conn);
    if (mode == 0) {
      if (f.conn.sessions.empty() || !f.worker->startup || f.worker->mailbox_head != f.worker->mailbox_tail ||
          f.worker->mailbox_failed || f.conn.out_queue.size() != 1 || f.closes)
        return false;
    } else {
      const bool rejected = f.conn.sessions.empty();
      f.service->Close(f.conn);
      if (!rejected || !f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || !PopWorkerExit(f.conn) ||
          f.closes != 1 || f.waits != 1 || f.post_after_close) {
        *detail = "mailbox full intake did not close and join";
        return false;
      }
    }
  }
  return true;
}
bool RelayMailboxFairness(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1)) return false;
  f.Phase(1); f.Phase(2);
  DrainLocal(f.conn);
  for (uint8_t i = 0; i < 64; ++i) {
    auto bytes = v8host::EncodeRunEnvelope(GuestRelay(1));
    bytes.back() = i;
    router::Worker::OnMessage(f.worker, sbox_msg_binary, bytes.data(), bytes.size());
    if (!f.Relay(1, 1, i)) return false;
    std::vector<uint8_t> frame;
    if (!f.conn.TakeOutput(&frame)) {
      *detail = "back-to-back relays starved worker mailbox at " + std::to_string(i);
      return false;
    }
    f.conn.CompleteOutput(frame.size());
    protocol::FrameHeader h;
    const uint8_t *payload, *body;
    size_t size, body_size;
    int32_t kind;
    if (protocol::DecodeAndValidateFrame(frame.data(), frame.size(), &h, &payload, &size) != protocol::DecodeStatus::kOk ||
        h.type != protocol::MessageType::RELAY_FROM_WORKER || h.run_id != 1 ||
        !protocol::DecodeRelayPayload(payload, size, &kind, &body, &body_size) ||
        kind != sbox_msg_binary || body_size != 1 || body[0] != i || f.conn.sessions.size() != 1 ||
        f.closes || f.worker->mailbox_failed || !f.conn.out_queue.empty()) return false;
  }
  return f.posts.size() == 65 && f.worker->mailbox_head == f.worker->mailbox_tail;
}
bool InlineReadMailbox(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1)) return false;
  DrainLocal(f.conn);
  struct Pipes {
    HANDLE server = INVALID_HANDLE_VALUE, client = INVALID_HANDLE_VALUE;
    ~Pipes() {
      if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
      if (server != INVALID_HANDLE_VALUE) ::CloseHandle(server);
    }
  } pipes;
  const std::wstring name = L"\\\\.\\pipe\\v8host-inline-" + std::to_wstring(::GetCurrentProcessId());
  pipes.server = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, 4096, 4096, 0, nullptr);
  pipes.client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED, nullptr);
  OVERLAPPED connect = {};
  connect.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  const bool connected = pipes.server != INVALID_HANDLE_VALUE && pipes.client != INVALID_HANDLE_VALUE && connect.hEvent &&
      (::ConnectNamedPipe(pipes.server, &connect) || ::GetLastError() == ERROR_PIPE_CONNECTED);
  if (connect.hEvent) ::CloseHandle(connect.hEvent);
  if (!connected) return false;
  f.conn.pipe = pipes.server;
  f.conn.dispatcher = f.service.get();
  std::vector<uint8_t> sent{1}, received(1);
  for (int i = 0; i < 64; ++i) {
    // Completed write guarantees the read has buffered data; no pending-read wake is needed.
    if (!PipeIo(pipes.client, true, &sent)) return false;
    const uint8_t startup[] = {1, 0, 0, 0};
    router::Worker::OnMessage(f.worker, sbox_msg_lifecycle, startup, sizeof(startup));
    DWORD size = 0;
    if (!f.conn.ReadFrame(received.data(), 1, &size, 3000) || size != 1 || received != sent ||
        f.conn.inline_reads != static_cast<uint32_t>(i + 1) || f.conn.sessions.empty() || f.closes ||
        f.worker->mailbox_failed || f.worker->mailbox_head != f.worker->mailbox_tail || !f.worker->startup) {
      *detail = "immediately completed read did not drain worker mailbox";
      return false;
    }
    DrainLocal(f.conn);
  }
  f.conn.pipe = INVALID_HANDLE_VALUE;
  return true;
}
bool HeldRelayBudget(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1))
    return false;
  DrainLocal(f.conn);
  for (int i = 0; i < 16; ++i)
    if (!f.Relay(1, 65512))
      return false;
  if (!f.Relay(1, 112) || f.conn.sessions.at(1)->runs.at(1)->queued_relay_bytes != protocol::kMaxQueuedRelayBytesPerRun ||
      !f.posts.empty() || !f.Relay(1, 0))
    return false;
  protocol::FrameHeader header;
  protocol::StatusCode code;
  if (!PopFrame(f.conn, &header, &code) || header.type != protocol::MessageType::RUN_ERROR || header.request_id != 0 ||
      code != protocol::StatusCode::ERROR_QUOTA || !f.conn.sessions.at(1)->runs.empty() || !f.posts.empty()) {
    *detail = "held relay budget exact cap/+1";
    return false;
  }
  f.Phase(1); f.Phase(2);
  return f.posts.empty();
}
struct CapturedBroker {
  HANDLE process = nullptr, output = nullptr;
  std::thread reader;
  std::mutex mutex;
  std::condition_variable changed;
  std::vector<HANDLE> workers;
  bool failed = false;
  std::string diagnostics;
  std::string lifecycle_failure;
  unsigned lifecycle_evidence = 0;
  std::string failure_selector;
  HANDLE lifecycle_held = nullptr;
  ~CapturedBroker() {
    if (process) {
      if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0) {
        {
          std::lock_guard<std::mutex> lock(mutex);
          std::printf("[failure broker reap] broker=%lu workers=%zu failed=%d\n[failure diagnostics] %s\n",
              ::GetProcessId(process), workers.size(), failed, diagnostics.c_str());
          for (HANDLE worker : workers)
            std::printf("[failure worker wait] worker=%lu wait=%lu\n", ::GetProcessId(worker), ::WaitForSingleObject(worker, 0));
        }
        std::printf("[cleanup] forced owned broker termination\n");
        ::TerminateProcess(process, 1);
        ::WaitForSingleObject(process, 5000);
      }
      ::CloseHandle(process);
    }
    if (reader.joinable())
      reader.join();
    if (output)
      ::CloseHandle(output);
    if (lifecycle_held)
      ::CloseHandle(lifecycle_held);
    for (HANDLE worker : workers)
      ::CloseHandle(worker);
  }
  bool Launch(std::string *detail) {
    *detail = "captured broker identity/capture/lifecycle setup";
    v8host::PayloadIdentity payload;
    std::vector<uint8_t> sid;
    LUID session;
    DWORD error;
    std::wstring endpoint;
    std::array<uint8_t, 32> key;
    if (!v8host::ResolvePayloadIdentity(ExecutableDirectory(), L"sbox.exe", L"v8host.dll", &payload, &error) ||
        !v8host::QueryCurrentSidAndSession(&sid, &session, &error) ||
        !v8host::DeriveEndpoint(sid, payload.plugin_set_id, BrokerMode::kShared, nullptr, &endpoint, &key))
      return false;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE write = nullptr;
    if (!::CreatePipe(&output, &write, &sa, 0))
      return false;
    ::SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = startup.hStdError = write;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    std::wstring exe = ExecutableDirectory() + L"\\sbox.exe";
    std::wstring command = L"\"" + exe + L"\" --broker --mode=shared --pipe=\"" + endpoint + L"\" --plugin v8host.dll";
    PROCESS_INFORMATION pi = {};
    const DWORD previous_size = ::GetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_FAILURE", nullptr, 0);
    std::string previous(previous_size, '\0');
    if (previous_size)
      ::GetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_FAILURE", previous.data(), previous_size);
    const DWORD event_previous_size = ::GetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_HELD_EVENT", nullptr, 0);
    std::string event_previous(event_previous_size, '\0');
    if (event_previous_size)
      ::GetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_HELD_EVENT", event_previous.data(), event_previous_size);
    if (!failure_selector.empty()) {
      const std::string name = "Local\\sbox-lifecycle-held-" + std::to_string(::GetCurrentProcessId()) +
          "-" + failure_selector;
      lifecycle_held = ::CreateEventA(nullptr, TRUE, FALSE, name.c_str());
      if (!lifecycle_held) {
        ::CloseHandle(write);
        return false;
      }
      ::SetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_HELD_EVENT", name.c_str());
      ::SetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_FAILURE", failure_selector.c_str());
    }
    const ULONGLONG launch_started = ::GetTickCount64();
    bool ok = ::CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
        ExecutableDirectory().c_str(), &startup, &pi) != FALSE;
    diagnostics += "[broker launch] duration_ms=" + std::to_string(::GetTickCount64() - launch_started) + "\n";
    if (!failure_selector.empty()) {
      ::SetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_FAILURE", previous_size ? previous.c_str() : nullptr);
      ::SetEnvironmentVariableA("SBOX_TEST_LIFECYCLE_HELD_EVENT", event_previous_size ? event_previous.c_str() : nullptr);
    }
    ::CloseHandle(write);
    if (!ok) {
      *detail = "captured broker launch failed";
      return false;
    }
    process = pi.hProcess;
    ::CloseHandle(pi.hThread);
    reader = std::thread([this] {
      std::string line;
      bool oversized = false;
      char chunk[1024];
      DWORD size;
      while (::ReadFile(output, chunk, sizeof(chunk), &size, nullptr) && size) {
        for (DWORD i = 0; i < size; ++i) {
          if (chunk[i] == '\n') {
            if (oversized) { line.clear(); oversized = false; continue; }
            while (!line.empty() && line.back() == '\r')
              line.pop_back();
            { std::lock_guard<std::mutex> lock(mutex); if (diagnostics.size() < 65536) diagnostics += line + "\n"; }
            unsigned long pid = 0;
            if (std::sscanf(line.c_str(), "[broker] target created: pid=%lu", &pid) == 1) {
              HANDLE held = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
              std::lock_guard<std::mutex> lock(mutex);
              if (!held || workers.size() >= 32 || std::any_of(workers.begin(), workers.end(),
                  [pid](HANDLE h) { return ::GetProcessId(h) == pid && ::WaitForSingleObject(h, 0) == WAIT_TIMEOUT; })) {
                failed = true;
                if (held)
                  ::CloseHandle(held);
              } else {
                workers.push_back(held);
                changed.notify_all();
                if (lifecycle_held)
                  ::SetEvent(lifecycle_held);
                std::printf("[captured] target created: pid=%lu\n", pid);
                std::fflush(stdout);
              }
            }
            if (line.rfind("[sbox-test] failure=", 0) == 0) {
              std::lock_guard<std::mutex> lock(mutex);
              lifecycle_failure = line;
              ++lifecycle_evidence;
            }
            line.clear();
          } else if (!oversized && line.size() < 4096) {
            line += chunk[i];
          } else {
            std::lock_guard<std::mutex> lock(mutex);
            failed = true;
            oversized = true;
            changed.notify_all();
          }
        }
      }
      std::lock_guard<std::mutex> lock(mutex);
      if (!line.empty() || oversized) failed = true;
      changed.notify_all();
    });
    const ULONGLONG deadline = ::GetTickCount64() + 5000;
    while (::GetTickCount64() < deadline) {
      if (::WaitNamedPipeW(endpoint.c_str(), 100))
        return true;
      if (::WaitForSingleObject(process, 10) == WAIT_OBJECT_0)
        break;
    }
    *detail = "captured endpoint did not become ready";
    return false;
  }
  bool Observe(size_t count) {
    std::unique_lock<std::mutex> lock(mutex);
    return changed.wait_for(lock, std::chrono::seconds(10), [&] { return failed || workers.size() >= count; }) &&
        !failed && workers.size() == count;
  }
  HANDLE Worker(size_t index) {
    std::lock_guard<std::mutex> lock(mutex);
    return !failed && index < workers.size() ? workers[index] : nullptr;
  }
  bool WorkersExited(size_t count) {
    if (!Observe(count)) return false;
    for (size_t i = 0; i < count; ++i) {
      HANDLE h = Worker(i);
      if (!h || ::WaitForSingleObject(h, 10000) != WAIT_OBJECT_0) return false;
      std::printf("[reaped] broker=%lu worker=%lu\n", ::GetProcessId(process), ::GetProcessId(h));
    }
    return true;
  }
  bool Reaped(size_t count) {
    if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0)
      return false;
    reader.join();
    std::printf("[reaped] broker=%lu\n", ::GetProcessId(process));
    if (failed || workers.size() != count) return false;
    for (HANDLE h : workers) {
      if (::WaitForSingleObject(h, 0) != WAIT_OBJECT_0) return false;
      std::printf("[reaped] broker=%lu worker=%lu\n", ::GetProcessId(process), ::GetProcessId(h));
    }
    return true;
  }
  bool ReapedAfterKill(size_t count) {
    if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0) return false;
    reader.join();
    std::printf("[reaped] killed broker=%lu\n", ::GetProcessId(process));
    return !failed && WorkersExited(count);
  }
};
bool OpenCaptured(CapturedBroker &broker, WireHarness &h, std::string *detail) {
  if (!broker.Launch(detail) ||
      !ConnectAndHandshake(BrokerMode::kShared, 900, &h.connection, &h.hello, detail) ||
      h.connection.broker_pid() != ::GetProcessId(broker.process))
    return false;
  auto config = LogicalConfig();
  config.broker_mode = 1;
  config.initial_token = sbox_token_restricted_same_access;
  config.delayed_integrity = sbox_integrity_untrusted;
  return h.Send(protocol::BuildCreateSessionFrame(h.Header(1), config)) &&
      h.Expect(protocol::MessageType::ACK, 1, 1) && h.Expect(protocol::MessageType::SESSION_READY, 0, 1);
}
protocol::StartRunPayload Script(const std::string &guest) {
  protocol::StartRunPayload start;
  start.tier_override = -1;
  start.guest_payload.assign(guest.begin(), guest.end());
  return start;
}
bool SendString(WireHarness &h, uint32_t id, const std::string &message) {
  auto header = h.Header(0, 1, id);
  header.type = protocol::MessageType::RELAY_TO_WORKER;
  return h.Send(protocol::BuildRelayFrame(header, sbox_msg_string,
      reinterpret_cast<const uint8_t *>(message.data()), message.size()));
}
bool ExpectString(WireHarness &h, uint32_t id, const std::string &message) {
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  int32_t kind;
  const uint8_t *body;
  size_t size;
  return h.Receive(&bytes, &header) && header.type == protocol::MessageType::RELAY_FROM_WORKER && header.run_id == id &&
      protocol::DecodeRelayPayload(bytes.data() + protocol::kFrameHeaderSize,
          bytes.size() - protocol::kFrameHeaderSize, &kind, &body, &size) && kind == sbox_msg_string &&
      std::string(reinterpret_cast<const char *>(body), size) == message;
}
bool ExpectResult(WireHarness &h, uint32_t id, protocol::ResultDisposition disposition) {
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  protocol::ResultPayload result;
  return h.Receive(&bytes, &header) && header.type == protocol::MessageType::RESULT && header.run_id == id &&
      header.request_id == 0 && protocol::DecodeResultPayload(bytes.data() + protocol::kFrameHeaderSize,
          bytes.size() - protocol::kFrameHeaderSize, &result) && result.disposition == disposition;
}
bool LifecycleFailure(unsigned failure, std::string *detail) {
  CapturedBroker broker;
  broker.failure_selector = std::to_string(failure);
  WireHarness h;
  if (!OpenCaptured(broker, h, detail) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), Script("host.postMessage('unexpected-run');"))) ||
      !h.Expect(protocol::MessageType::ACK, 2, 1, 1) ||
      (failure != 1 && !h.Expect(protocol::MessageType::STARTUP_READY, 0, 1)) ||
      !h.Expect(protocol::MessageType::WORKER_EXIT, 0, 1)) {
    *detail = "failed child readiness/EXIT ordering";
    return false;
  }
  // A live control barrier proves there was no synthetic result/security/second EXIT.
  if (!h.Send(protocol::BuildCancelRunFrame(h.Header(3, 1, 1))) ||
      !h.Expect(protocol::MessageType::ACK, 3, 1, 1))
    return false;
  h.connection.Close();
  const std::string expected = "[sbox-test] failure=" + std::to_string(failure) +
      " lower=" + (failure == 1 ? "0" : "1") + " run=0 shutdown=1 end=1";
  if (!broker.Reaped(1) || broker.lifecycle_evidence != 1 || broker.lifecycle_failure != expected) {
    *detail = "selected worker branch/resource cleanup not observed (count=" + std::to_string(broker.lifecycle_evidence) + ",size=" + std::to_string(broker.lifecycle_failure.size()) + "): " + broker.lifecycle_failure;
    return false;
  }
  return true;
}
bool LifecycleFailStartup(std::string *d) { return LifecycleFailure(1, d); }
bool LifecycleFailSecurity(std::string *d) { return LifecycleFailure(2, d); }
bool PingPostFail(std::string *d) { return LifecycleFailure(3, d); }
bool RealCancelOrdering(bool cancel_first, std::string *detail) {
  CapturedBroker broker;
  WireHarness h;
  if (!OpenCaptured(broker, h, detail) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), Script(
          "host.onmessage=function(m){host.complete();};host.postMessage('armed');"))) ||
      !h.Expect(protocol::MessageType::ACK, 2, 1, 1) || !h.Expect(protocol::MessageType::STARTUP_READY, 0, 1) ||
      !h.Expect(protocol::MessageType::SECURITY_READY, 0, 1) || !ExpectString(h, 1, "armed"))
    return false;
  if (!cancel_first && (!SendString(h, 1, "complete") ||
      !ExpectResult(h, 1, protocol::ResultDisposition::kCompleted)))
    return false;
  if (!h.Send(protocol::BuildStartRunFrame(h.Header(3, 1, 2), Script(
          "host.onmessage=function(m){host.postMessage('next:'+m);host.complete();};"))) ||
      !h.Expect(protocol::MessageType::ACK, 3, 1, 2) || !SendString(h, 2, "held") ||
      !h.Send(protocol::BuildCancelRunFrame(h.Header(4, 1, 1))) ||
      !h.Expect(protocol::MessageType::ACK, 4, 1, 1) ||
      (cancel_first && !ExpectResult(h, 1, protocol::ResultDisposition::kCancelled)) ||
      !ExpectString(h, 2, "next:held") || !ExpectResult(h, 2, protocol::ResultDisposition::kCompleted) ||
      !SendString(h, 1, "late") || !h.Send(protocol::BuildCancelRunFrame(h.Header(5, 1, 1))) ||
      !h.Expect(protocol::MessageType::ACK, 5, 1, 1)) {
    *detail = "cancel terminal/successor FIFO/late-output barrier";
    return false;
  }
  h.connection.Close();
  return broker.Reaped(1);
}
bool CancelsFirst(std::string *d) { return RealCancelOrdering(true, d); }
bool CompletesFirst(std::string *d) { return RealCancelOrdering(false, d); }
bool RealTwoRunReuse(std::string *detail) {
  CapturedBroker broker;
  WireHarness h;
  if (!OpenCaptured(broker, h, detail) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), Script(
          "host.onmessage=function(m){host.postMessage('A:'+m);if(m==='finish')host.complete();};"))) ||
      !h.Expect(protocol::MessageType::ACK, 2, 1, 1) || !h.Expect(protocol::MessageType::STARTUP_READY, 0, 1) ||
      !h.Expect(protocol::MessageType::SECURITY_READY, 0, 1) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(3, 1, 2), Script(
          "var n=0;host.onmessage=function(m){host.postMessage('B:'+m);if(++n===2)host.complete();};"))) ||
      !SendString(h, 2, "one") || !SendString(h, 2, "two") || !h.Expect(protocol::MessageType::ACK, 3, 1, 2) ||
      !SendString(h, 1, "hold") || !ExpectString(h, 1, "A:hold") ||
      !SendString(h, 1, "finish") || !ExpectString(h, 1, "A:finish") ||
      !ExpectResult(h, 1, protocol::ResultDisposition::kCompleted) || !ExpectString(h, 2, "B:one") ||
      !ExpectString(h, 2, "B:two") || !ExpectResult(h, 2, protocol::ResultDisposition::kCompleted)) {
    *detail = "real held B dispatched before A or lost FIFO";
    return false;
  }
  for (uint32_t id = 3; id <= 5; ++id) {
    auto start = Script("host.complete();");
    if (id == 3)
      start.tier_override = v8host::kTierTrusted;
    else if (id == 4) {
      start.has_engine_override = true;
      start.engine_filename = "other.dll";
    } else {
      start.has_snapshot = true;
      start.snapshot_path = "other.snapshot";
    }
    std::vector<uint8_t> bytes;
    protocol::FrameHeader header;
    protocol::ErrorPayload error;
    if (!h.Send(protocol::BuildStartRunFrame(h.Header(id + 1, 1, id), start)) ||
        !h.Expect(protocol::MessageType::ACK, id + 1, 1, id) || !h.Receive(&bytes, &header) ||
        header.type != protocol::MessageType::RUN_ERROR || header.run_id != id || header.request_id != 0 ||
        !protocol::DecodeErrorPayload(bytes.data() + protocol::kFrameHeaderSize,
            bytes.size() - protocol::kFrameHeaderSize, &error) ||
        error.status_code != protocol::StatusCode::ERROR_PROFILE_ALREADY_BOUND) {
      *detail = "real profile conflict id=" + std::to_string(id) + " type=" +
          std::to_string(static_cast<unsigned>(header.type)) + " code=" +
          std::to_string(static_cast<unsigned>(error.status_code));
      return false;
    }
  }
  if (!h.Send(protocol::BuildStartRunFrame(h.Header(7, 1, 6), Script("host.postMessage('reused');host.complete();"))) ||
      !h.Expect(protocol::MessageType::ACK, 7, 1, 6) || !ExpectString(h, 6, "reused") ||
      !ExpectResult(h, 6, protocol::ResultDisposition::kCompleted) ||
      !h.Send(protocol::BuildCloseSessionFrame(h.Header(8))) || !h.Expect(protocol::MessageType::ACK, 8, 1)) {
    *detail = "same worker reuse/sentinel terminal barrier";
    return false;
  }
  h.connection.Close();
  return broker.Reaped(1);
}
bool LiveWorkerCleanup(bool close, std::string *detail) {
  CapturedBroker broker;
  WireHarness h;
  if (!OpenCaptured(broker, h, detail) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), Script(
          "host.onmessage=function(m){host.postMessage(m);};host.postMessage('armed');"))) ||
      !h.Expect(protocol::MessageType::ACK, 2, 1, 1) || !h.Expect(protocol::MessageType::STARTUP_READY, 0, 1) ||
      !h.Expect(protocol::MessageType::SECURITY_READY, 0, 1) || !ExpectString(h, 1, "armed")) {
    *detail = "live worker sentinel";
    return false;
  }
  if (close && (!h.Send(protocol::BuildCloseSessionFrame(h.Header(3))) ||
      !ExpectResult(h, 1, protocol::ResultDisposition::kCancelled) || !h.Expect(protocol::MessageType::ACK, 3, 1))) {
    *detail = "CLOSE live worker terminal/ACK barrier";
    return false;
  }
  h.connection.Close();
  if (!broker.Reaped(1)) {
    *detail = "held live worker did not signal or respawned";
    return false;
  }
  return true;
}
bool CloseLiveWorker(std::string *detail) { return LiveWorkerCleanup(true, detail); }
bool DisconnectLiveWorker(std::string *detail) { return LiveWorkerCleanup(false, detail); }
bool StartSpawn(std::string *detail) {
  CapturedBroker broker;
  if (!broker.Launch(detail))
    return false;
  WireHarness h;
  if (!ConnectAndHandshake(BrokerMode::kShared, 900, &h.connection, &h.hello, detail) ||
      h.connection.broker_pid() != ::GetProcessId(broker.process)) {
    *detail = "not connected to captured broker";
    return false;
  }
  auto expect = [&](protocol::MessageType type, uint32_t request, uint32_t session, uint32_t run,
                    const char *event) {
    if (!h.Expect(type, request, session, run)) return false;
    std::printf("[start-spawn] %s\n", event);
    return true;
  };
  if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(1), [] {
        auto config = LogicalConfig(); config.broker_mode = 1;
        config.initial_token = sbox_token_restricted_same_access;
        config.delayed_integrity = sbox_integrity_untrusted; return config;
      }())) || !expect(protocol::MessageType::ACK, 1, 1, 0, "CREATE ACK") ||
      !expect(protocol::MessageType::SESSION_READY, 0, 1, 0, "SESSION_READY")) {
    *detail = "CREATE readiness";
    return false;
  }
  protocol::StartRunPayload start;
  start.tier_override = -1;
  const std::string guest = "var n=0;host.onmessage=function(m){if(typeof m==='string')host.postMessage('echo:'+m);"
      "else {var a=new Uint8Array(m);a[0]=66;host.postMessageBinary(m);}if(++n===2)host.complete();};";
  start.guest_payload.assign(guest.begin(), guest.end());
  auto relay = h.Header(0, 1, 1);
  relay.type = protocol::MessageType::RELAY_TO_WORKER;
  const uint8_t binary[] = {1, 2, 3};
  if (!h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), start)) ||
      !h.Send(protocol::BuildRelayFrame(relay, sbox_msg_string, reinterpret_cast<const uint8_t *>("one"), 3)) ||
      !h.Send(protocol::BuildRelayFrame(relay, sbox_msg_binary, binary, sizeof(binary))) ||
      !expect(protocol::MessageType::ACK, 2, 1, 1, "START ACK") ||
      !expect(protocol::MessageType::STARTUP_READY, 0, 1, 0, "STARTUP") ||
      !expect(protocol::MessageType::SECURITY_READY, 0, 1, 0, "SECURITY")) {
    *detail = "START/readiness";
    return false;
  }
  for (int i = 0; i < 2; ++i) {
    std::vector<uint8_t> bytes;
    protocol::FrameHeader header;
    int32_t kind;
    const uint8_t *body;
    size_t size;
    if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::RELAY_FROM_WORKER ||
        header.run_id != 1 || !protocol::DecodeRelayPayload(bytes.data() + protocol::kFrameHeaderSize,
            bytes.size() - protocol::kFrameHeaderSize, &kind, &body, &size) ||
        (i == 0 ? kind != sbox_msg_string || std::string(reinterpret_cast<const char *>(body), size) != "echo:one"
                : kind != sbox_msg_binary || std::vector<uint8_t>(body, body + size) != std::vector<uint8_t>{66, 2, 3})) {
      *detail = "JS relay echo " + std::to_string(i);
      return false;
    }
    std::printf("[start-spawn] RELAY echo kind=%s bytes=%zu\n", i == 0 ? "string" : "binary", size);
  }
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  protocol::ResultPayload result;
  if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::RESULT || header.run_id != 1 ||
      !protocol::DecodeResultPayload(bytes.data() + protocol::kFrameHeaderSize,
          bytes.size() - protocol::kFrameHeaderSize, &result) || result.disposition != protocol::ResultDisposition::kCompleted) {
    *detail = "sole RESULT";
    return false;
  }
  std::printf("[start-spawn] RESULT completed count=1\n");
  if (!h.Send(protocol::BuildCloseSessionFrame(h.Header(3))) || !h.Expect(protocol::MessageType::ACK, 3, 1)) {
    *detail = "sole RESULT/CLOSE barrier";
    return false;
  }
  h.connection.Close();
  if (!broker.Reaped(1)) {
    *detail = "spawn count/held worker exit";
    return false;
  }
  return true;
}
bool UnknownTypeIgnored(std::string *detail) {
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  for (uint16_t type : {0x000b, 0x0104, 0x0202, 0xffff}) {
    auto header = ControlHeader(0, 0);
    header.type = static_cast<protocol::MessageType>(type);
    header.payload_length = 3;
    std::vector<uint8_t> bytes;
    protocol::EncodeHeader(header, bytes);
    bytes.insert(bytes.end(), {0xff, 0, 0x80});
    if (!LocalRoute(service, conn, bytes) || conn.state != router::ConnState::kOpen || !conn.out_queue.empty() ||
        !conn.sessions.empty() || conn.request_cache.size() != 0) {
      *detail = "unknown optional type was not consumed without effects";
      return false;
    }
  }
  WireHarness h;
  if (!h.Open(detail))
    return false;
  auto header = h.Header(1, 0);
  header.type = static_cast<protocol::MessageType>(0xffff);
  std::vector<uint8_t> bytes;
  protocol::EncodeHeader(header, bytes);
  // Same request id must remain fresh, and no unknown-type reply may precede ACK.
  return h.Send(std::move(bytes)) && h.Send(protocol::BuildCreateSessionFrame(h.Header(1), LogicalConfig())) &&
      h.Expect(protocol::MessageType::ACK, 1, 1) && h.Expect(protocol::MessageType::SESSION_READY, 0, 1) && h.Finish();
}
bool UnknownMustUnderstand(std::string *detail) {
  WireHarness h;
  if (!h.Open(detail))
    return false;
  auto unknown = h.Header(17, 0, 3);
  unknown.type = static_cast<protocol::MessageType>(0xffff);
  unknown.flags = protocol::kFlagMustUnderstand;
  unknown.payload_length = 1;
  std::vector<uint8_t> bytes;
  protocol::EncodeHeader(unknown, bytes);
  bytes.push_back(0xff);
  // Delay the read until exit to prove the error was drained, not just enqueued.
  if (!h.Send(std::move(bytes)) || ::WaitForSingleObject(h.process, 3000) != WAIT_OBJECT_0) {
    *detail = "unsupported mandatory type did not close the broker";
    return false;
  }
  protocol::FrameHeader header;
  const uint8_t *payload;
  size_t size;
  protocol::ErrorPayload error;
  if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::ERROR ||
      header.conn_id != unknown.conn_id || header.session_id != unknown.session_id || header.run_id != unknown.run_id ||
      header.request_id != unknown.request_id || header.flags != unknown.flags ||
      header.version_major != unknown.version_major || header.version_minor != unknown.version_minor ||
      protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &header, &payload, &size) !=
          protocol::DecodeStatus::kOk ||
      !protocol::DecodeErrorPayload(payload, size, &error) ||
      error.status_code != protocol::StatusCode::ERROR_UNSUPPORTED_MESSAGE) {
    *detail = "missing or incorrectly correlated ERROR_UNSUPPORTED_MESSAGE";
    return false;
  }
  return h.Closed();
}
bool HelloVersionReject(std::string *detail) {
  WireHarness h;
  BrokerRendezvous rendezvous(ExecutableDirectory(), BrokerMode::kDedicated);
  if (rendezvous.ConnectOrLaunch(&h.connection) != RendezvousStatus::kOk)
    return false;
  h.process = ::OpenProcess(SYNCHRONIZE, FALSE, h.connection.broker_pid());
  if (!h.process)
    return false;
  auto hello = ControlHeader(901, 0);
  hello.conn_id = 0;
  ++hello.version_major;
  // Read only after server teardown, so unread reject delivery is deterministic.
  if (!h.Send(protocol::BuildHelloFrame(hello)) || ::WaitForSingleObject(h.process, 3000) != WAIT_OBJECT_0) {
    *detail = "version reject did not finish bounded teardown";
    return false;
  }
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  const uint8_t *payload;
  size_t size;
  protocol::ErrorPayload error;
  if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::ERROR ||
      header.request_id != hello.request_id || header.conn_id == 0 || header.conn_id == UINT32_MAX ||
      header.version_major != protocol::kWireVersionMajor || header.version_minor != protocol::kWireVersionMinor ||
      header.session_id != 0 || header.run_id != 0 ||
      protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &header, &payload, &size) !=
          protocol::DecodeStatus::kOk ||
      !protocol::DecodeErrorPayload(payload, size, &error) || error.status_code != protocol::StatusCode::ERROR_VERSION) {
    *detail = "client did not read ERROR_VERSION after broker exit";
    return false;
  }
  return h.Closed();
}
bool CreateReady(std::string *detail) {
  WireHarness h;
  if (!h.Open(detail))
    return false;
  if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(1), LogicalConfig())) ||
      !h.Expect(protocol::MessageType::ACK, 1, 1) || !h.Expect(protocol::MessageType::SESSION_READY, 0, 1) ||
      !h.Send(protocol::BuildCloseSessionFrame(h.Header(2))) || !h.Expect(protocol::MessageType::ACK, 2, 1)) {
    *detail = "CREATE ACK/READY then CLOSE ACK";
    return false;
  }
  return h.Finish();
}

bool PersistentControl(std::string *detail) {
  WireHarness h;
  if (!h.Open(detail))
    return false;
  for (uint32_t id = 1; id <= 3; ++id) {
    if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(id, id), LogicalConfig())) ||
        !h.Expect(protocol::MessageType::ACK, id, id) || !h.Expect(protocol::MessageType::SESSION_READY, 0, id))
      return false;
  }
  if (!h.Send(protocol::BuildCancelRunFrame(h.Header(4, 99, 99))) || !h.Expect(protocol::MessageType::ACK, 4, 99, 99))
    return false;
  auto relay = h.Header(0, 99, 99);
  relay.type = protocol::MessageType::RELAY_TO_WORKER;
  if (!h.Send(protocol::BuildRelayFrame(relay, sbox_msg_binary, nullptr, 0)) ||
      !h.Send(protocol::BuildCloseSessionFrame(h.Header(5, 2))) || !h.Expect(protocol::MessageType::ACK, 5, 2))
    return false;
  return h.Finish();
}
bool HeaderDirectionReject(std::string *detail) {
  for (int test = 0; test < 18; ++test) {
    WireHarness h;
    if (!h.Open(detail))
      return false;
    auto header = h.Header(1);
    std::vector<uint8_t> bytes;
    switch (test) {
      case 0:
        ++header.conn_id;
        break;
      case 1:
        header.session_id = 0;
        break;
      case 2:
        header.run_id = 1;
        break;
      case 3:
        header.request_id = 0;
        break;
      case 4:
        ++header.version_major;
        break;
      case 5:
        ++header.version_minor;
        break;
      default:
        break;
    }
    bytes = protocol::BuildCreateSessionFrame(header, LogicalConfig());
    if (test == 6)
      bytes[0] ^= 1;
    if (test == 7)
      bytes.push_back(0);
    if (test == 8) {
      bytes = protocol::BuildAckFrame(header);
    }
    if (test == 9) {
      bytes = protocol::BuildSessionReadyFrame(header);
    }
    if (test == 10) {
      bytes = protocol::BuildCloseSessionFrame(header);
      bytes.push_back(0);
    }
    if (test == 11) {
      bytes = protocol::BuildCreateSessionFrame(header, LogicalConfig());
      bytes[32] = 99;
    }
    if (test == 12) {
      bytes.resize(protocol::kMaxFrameSize + 1, 0);
    }
    if (test == 13) {
      header.session_id = UINT32_MAX;
      bytes = protocol::BuildCreateSessionFrame(header, LogicalConfig());
    }
    if (test == 14) {
      header.request_id = UINT32_MAX;
      bytes = protocol::BuildCreateSessionFrame(header, LogicalConfig());
    }
    if (test == 15) {
      header.run_id = UINT32_MAX;
      bytes = protocol::BuildCancelRunFrame(header);
    }
    if (test == 16 || test == 17) {
      header.run_id = 1;
      header.request_id = 0;
      header.type = protocol::MessageType::RELAY_TO_WORKER;
      bytes = protocol::BuildRelayFrame(header, sbox_msg_lifecycle, nullptr, 0);
      if (test == 17) {
        header.payload_length = 0;
        bytes.clear();
        protocol::EncodeHeader(header, bytes);
      }
    }
    if (!h.Send(std::move(bytes)) || !h.Closed()) {
      *detail = "header/direction/malformed case=" + std::to_string(test);
      return false;
    }
  }
  return true;
}
bool ControlCache(std::string *detail) {
  WireHarness h;
  if (!h.Open(detail))
    return false;
  auto create = protocol::BuildCreateSessionFrame(h.Header(1), LogicalConfig());
  if (!h.Send(create) || !h.Expect(protocol::MessageType::ACK, 1, 1) ||
      !h.Expect(protocol::MessageType::SESSION_READY, 0, 1) || !h.Send(create) ||
      !h.Expect(protocol::MessageType::ACK, 1, 1) || !h.Send(protocol::BuildCloseSessionFrame(h.Header(2))) ||
      !h.Expect(protocol::MessageType::ACK, 2, 1))
    return false;
  for (uint32_t request = 3; request <= 257; ++request) {
    if (!h.Send(protocol::BuildCancelRunFrame(h.Header(request, 99, 99))) ||
        !h.Expect(protocol::MessageType::ACK, request, 99, 99))
      return false;
  }
  if (!h.Send(create))
    return false;
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  const uint8_t *payload;
  size_t size;
  protocol::ErrorPayload error;
  if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::ERROR ||
      protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &header, &payload, &size) !=
          protocol::DecodeStatus::kOk ||
      !protocol::DecodeErrorPayload(payload, size, &error) ||
      error.status_code != protocol::StatusCode::ERROR_STALE_REQUEST || !h.Finish())
    return false;
  WireHarness mismatch;
  if (!mismatch.Open(detail))
    return false;
  auto config = LogicalConfig();
  if (!mismatch.Send(protocol::BuildCreateSessionFrame(mismatch.Header(1), config)) ||
      !mismatch.Expect(protocol::MessageType::ACK, 1, 1) ||
      !mismatch.Expect(protocol::MessageType::SESSION_READY, 0, 1))
    return false;
  config.initial_token = sbox_token_limited;
  if (!mismatch.Send(protocol::BuildCreateSessionFrame(mismatch.Header(1), config)) || !mismatch.Closed())
    return false;
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  for (uint32_t request = 1; request <= 257; ++request) {
    if (!LocalRoute(service, conn, protocol::BuildCancelRunFrame(ControlHeader(request, 1, 1))))
      return false;
    DrainLocal(conn);
    if (conn.request_cache.size() != (std::min)(request, 256u))
      return false;
  }
  if (!LocalRoute(service, conn, protocol::BuildCancelRunFrame(ControlHeader(1, 1, 1))))
    return false;
  protocol::StatusCode code;
  if (!PopFrame(conn, &header, &code) || code != protocol::StatusCode::ERROR_STALE_REQUEST || !conn.sessions.empty())
    return false;
  auto changed = ControlHeader(257, 2, 1);
  if (LocalRoute(service, conn, protocol::BuildCancelRunFrame(changed)))
    return false;
  return true;
}
bool SessionQuota32(std::string *detail) {
  WireHarness h;
  if (!h.Open(detail))
    return false;
  for (uint32_t id = 1; id <= 32; ++id) {
    if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(id, id), LogicalConfig())) ||
        !h.Expect(protocol::MessageType::ACK, id, id) || !h.Expect(protocol::MessageType::SESSION_READY, 0, id))
      return false;
  }
  if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(33, 33), LogicalConfig())))
    return false;
  std::vector<uint8_t> bytes;
  protocol::FrameHeader header;
  const uint8_t *payload;
  size_t size;
  protocol::ErrorPayload error;
  if (!h.Receive(&bytes, &header) || header.type != protocol::MessageType::ERROR || header.request_id != 33 ||
      header.session_id != 33 ||
      protocol::DecodeAndValidateFrame(bytes.data(), bytes.size(), &header, &payload, &size) !=
          protocol::DecodeStatus::kOk ||
      !protocol::DecodeErrorPayload(payload, size, &error) || error.status_code != protocol::StatusCode::ERROR_QUOTA ||
      !h.Send(protocol::BuildCloseSessionFrame(h.Header(34))) || !h.Expect(protocol::MessageType::ACK, 34, 1) ||
      !h.Send(protocol::BuildCreateSessionFrame(h.Header(35, 34), LogicalConfig())) ||
      !h.Expect(protocol::MessageType::ACK, 35, 34) || !h.Expect(protocol::MessageType::SESSION_READY, 0, 34))
    return false;
  return h.Finish();
}
bool IdRetirement(std::string *detail) {
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  auto create = protocol::BuildCreateSessionFrame(ControlHeader(1), LogicalConfig());
  if (!LocalRoute(service, conn, create))
    return false;
  DrainLocal(conn);
  auto *session = conn.sessions.at(1).get();
  session->worker = std::make_unique<router::Worker>();
  session->worker->active_run_id = 5;
  session->worker->pending_run_ids = {5};
  auto owned_run = std::make_unique<router::Run>();
  owned_run->session = session;
  owned_run->run_id = 5;
  auto *run = owned_run.get();
  session->runs.emplace(5, std::move(owned_run));
  bool removed_before_emit = false;
  session->terminal_removed = [&] {
    removed_before_emit = !conn.sessions.contains(1) && session->runs.empty() && conn.out_queue.empty();
  };
  HANDLE grabbed = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!grabbed || !release) {
    if (grabbed)
      ::CloseHandle(grabbed);
    if (release)
      ::CloseHandle(release);
    return false;
  }
  bool contender_safe = false;
  std::thread contender([&] {
    ::SetEvent(grabbed);
    if (::WaitForSingleObject(release, 3000) == WAIT_OBJECT_0)
      contender_safe = session->state == router::SessionState::kClosed && session->session_id == 1 &&
          run->state == router::RunState::kCancelled && !run->TryTerminal(router::RunState::kCompleted);
  });
  bool retired = ::WaitForSingleObject(grabbed, 3000) == WAIT_OBJECT_0 &&
      LocalRoute(service, conn, protocol::BuildCloseSessionFrame(ControlHeader(2))) && conn.sessions.empty() &&
      conn.retired_sessions.size() == 1 && conn.retired_sessions.front().get() == session &&
      session->retired_runs.size() == 1 && session->retired_runs.front().get() == run && removed_before_emit &&
      session->worker->active_run_id == 0 && session->worker->pending_run_ids.empty();
  ::SetEvent(release);
  contender.join();
  ::CloseHandle(grabbed);
  ::CloseHandle(release);
  if (!retired || !contender_safe) {
    *detail = "CLOSE did not remove ids and retain Session/Run for a delayed contender";
    return false;
  }
  protocol::FrameHeader terminal;
  if (!PopFrame(conn, &terminal) || terminal.type != protocol::MessageType::RESULT || terminal.run_id != 5 ||
      !PopFrame(conn, &terminal) || terminal.type != protocol::MessageType::ACK || terminal.request_id != 2 ||
      !conn.out_queue.empty() || !LocalRoute(service, conn, protocol::BuildCloseSessionFrame(ControlHeader(2))) ||
      conn.retired_sessions.size() != 1 || !PopFrame(conn, &terminal) || terminal.type != protocol::MessageType::ACK ||
      !conn.out_queue.empty())
    return false;
  if (!LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(3), LogicalConfig())))
    return false;
  protocol::FrameHeader header;
  protocol::StatusCode code;
  if (!PopFrame(conn, &header, &code) || code != protocol::StatusCode::ERROR_BAD_STATE || !conn.sessions.empty())
    return false;
  if (!LocalRoute(service, conn, create))
    return false; // Replay ACK only, never recreate.
  if (!PopFrame(conn, &header) || header.type != protocol::MessageType::ACK || !conn.sessions.empty())
    return false;
  {
    router::Connection exhausted;
    OpenLocal(exhausted);
    if (LocalRoute(service, exhausted, protocol::BuildCreateSessionFrame(ControlHeader(4, UINT32_MAX), LogicalConfig())) ||
        !exhausted.sessions.empty() || ::WaitForSingleObject(exhausted.stop, 0) != WAIT_OBJECT_0) {
      *detail = "exhausted id accepted or connection not stopped";
      return false;
    }
  }
  if (!LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(5, 2), LogicalConfig())))
    return false;
  DrainLocal(conn);
  if (LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(6, 2), LogicalConfig()))) {
    *detail = "fresh create reused live id";
    return false;
  }
  auto *second_session = conn.sessions.at(2).get();
  auto second_run = std::make_unique<router::Run>();
  second_run->session = second_session;
  second_run->run_id = 6;
  auto *disconnect_contender = second_run.get();
  second_session->runs.emplace(6, std::move(second_run));
  bool removed_on_disconnect = false;
  second_session->terminal_removed = [&] { removed_on_disconnect = !conn.sessions.contains(2); };
  service.Close(conn);
  return removed_on_disconnect && conn.sessions.empty() && conn.retired_sessions.size() == 2 &&
      second_session->state == router::SessionState::kClosed && second_session->retired_runs.size() == 1 &&
      disconnect_contender->state == router::RunState::kBrokerLost &&
      !disconnect_contender->TryTerminal(router::RunState::kCompleted) && conn.out_queue.empty();
}
std::vector<uint8_t> SizedFrame(size_t size) {
  auto h = ControlHeader(1);
  h.type = protocol::MessageType::ERROR;
  h.payload_length = static_cast<uint32_t>(size) - protocol::kFrameHeaderSize;
  std::vector<uint8_t> bytes;
  protocol::EncodeHeader(h, bytes);
  bytes.resize(size, 0);
  return bytes;
}
bool ControlBudget(std::string *detail) {
  for (bool byte_limit : {false, true}) {
    router::Connection conn;
    conn.writer_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!conn.writer_release || !conn.StartWriter())
      return false;
    bool passed = true;
    if (byte_limit) {
      size_t remaining = protocol::kMaxControlQueueBytes;
      while (remaining) {
        size_t size = (std::min)(remaining, static_cast<size_t>(protocol::kMaxFrameSize));
        passed = passed && conn.Enqueue(SizedFrame(size));
        remaining -= size;
      }
      passed =
          passed && conn.out_control_bytes == protocol::kMaxControlQueueBytes && !conn.Enqueue(std::vector<uint8_t>(1));
    } else {
      for (size_t i = 0; i < protocol::kMaxControlQueueRequests; ++i)
        passed = passed && conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)));
      passed = passed && conn.out_control_requests == protocol::kMaxControlQueueRequests &&
          !conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1)));
    }
    conn.Stop();
    conn.JoinWriter();
    ::CloseHandle(conn.writer_release);
    conn.writer_release = nullptr;
    if (!passed || conn.writers_started != 1 || conn.writers_joined != 1) {
      *detail = "paused writer control budget boundary";
      return false;
    }
  }

  router::Connection bytes_conn;
  size_t remaining = protocol::kMaxControlQueueBytes - protocol::kFrameHeaderSize;
  while (remaining) {
    size_t size = (std::min)(remaining, static_cast<size_t>(protocol::kMaxFrameSize));
    if (!bytes_conn.Enqueue(SizedFrame(size)))
      return false;
    remaining -= size;
  }
  if (bytes_conn.Enqueue(SizedFrame(protocol::kFrameHeaderSize + 1)) ||
      bytes_conn.out_control_bytes != protocol::kMaxControlQueueBytes - protocol::kFrameHeaderSize) {
    *detail = "valid-frame bytes cap plus one";
    return false;
  }
  router::Connection conn;
  if (!conn.Enqueue(protocol::BuildAckFrame(ControlHeader(1))))
    return false;
  std::vector<uint8_t> frame;
  if (!conn.TakeOutput(&frame) || conn.out_control_requests != 1 || conn.DrainOutput(0))
    return false;
  conn.CompleteOutput(frame.size());
  return conn.out_control_requests == 0 && conn.out_control_bytes == 0 && conn.DrainOutput(0);
}
bool StartAdmissionValidation(std::string *detail) {
  RouterFixture f;
  if (!f.Create())
    return false;
  DrainLocal(f.conn);
  protocol::StartRunPayload start;
  start.guest_payload = {'x'};
  auto unknown = start;
  unknown.tier_override = -1;
  router::BoundProfile valid;
  if (!router::PrepareProfile(LogicalConfig(), unknown, ExecutableDirectory(), &valid)) return false;
  for (uint32_t session : {99, 1}) {
    start.tier_override = session == 99 ? -1 : 2;
    if (!LocalRoute(*f.service, f.conn, protocol::BuildStartRunFrame(ControlHeader(session == 99 ? 2 : 3, session, 1), start)))
      return false;
    protocol::FrameHeader header;
    protocol::StatusCode code;
    if (!PopFrame(f.conn, &header, &code) || header.type != protocol::MessageType::ERROR ||
        code != protocol::StatusCode::ERROR_BAD_STATE || f.spawns || f.conn.sessions.size() != 1 ||
        f.conn.sessions.contains(99) || !f.conn.retired_sessions.empty() || f.conn.sessions.at(1)->profile_bound ||
        f.conn.sessions.at(1)->worker || !f.conn.sessions.at(1)->runs.empty()) {
      *detail = "invalid/unknown START spawned or bound profile";
      return false;
    }
  }
  WireHarness h;
  if (!h.Open(detail) || !h.Send(protocol::BuildCreateSessionFrame(h.Header(1), LogicalConfig())) ||
      !h.Expect(protocol::MessageType::ACK, 1, 1) || !h.Expect(protocol::MessageType::SESSION_READY, 0, 1) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 99, 1), unknown)) ||
      !h.Expect(protocol::MessageType::ERROR, 2, 99, 1) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(3, 1, 1), start)) ||
      !h.Expect(protocol::MessageType::ERROR, 3, 1, 1) || !h.Send(protocol::BuildCloseSessionFrame(h.Header(4))) ||
      !h.Expect(protocol::MessageType::ACK, 4, 1))
    return false;
  return h.Finish();
}

bool ConnectionJoined(std::string *detail) {
  router::Connection conn;
  const std::wstring name = L"\\\\.\\pipe\\v8host-join-" + std::to_wstring(::GetCurrentProcessId());
  conn.pipe = ::CreateNamedPipeW(
      name.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1,
      4096,
      4096,
      0,
      nullptr);
  if (conn.pipe == INVALID_HANDLE_VALUE)
    return false;
  HANDLE client = ::CreateFileW(
      name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  OVERLAPPED connect = {};
  connect.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  const bool connected = client != INVALID_HANDLE_VALUE &&
      (::ConnectNamedPipe(conn.pipe, &connect) || ::GetLastError() == ERROR_PIPE_CONNECTED);
  if (connect.hEvent)
    ::CloseHandle(connect.hEvent);
  conn.read_pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  conn.write_pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  bool passed = connected && conn.read_pending && conn.write_pending;
  std::thread reader;
  std::atomic<bool> read_done{false};
  if (passed) {
    reader = std::thread([&] {
      std::vector<uint8_t> bytes(protocol::kMaxFrameSize);
      DWORD size = 0;
      read_done = !conn.ReadFrame(bytes.data(), static_cast<DWORD>(bytes.size()), &size, INFINITE);
    });
    passed = conn.StartWriter() && conn.Enqueue(SizedFrame(protocol::kMaxFrameSize)) &&
        ::WaitForSingleObject(conn.read_pending, 3000) == WAIT_OBJECT_0 &&
        ::WaitForSingleObject(conn.write_pending, 3000) == WAIT_OBJECT_0;
  }
  conn.Stop();
  conn.JoinWriter();
  if (reader.joinable())
    reader.join();
  passed = passed && read_done && conn.active_io == 0 && conn.writers_started == 1 && conn.writers_joined == 1;
  if (conn.read_pending)
    ::CloseHandle(conn.read_pending);
  if (conn.write_pending)
    ::CloseHandle(conn.write_pending);
  conn.read_pending = conn.write_pending = nullptr;
  if (client != INVALID_HANDLE_VALUE)
    ::CloseHandle(client);
  ::DisconnectNamedPipe(conn.pipe);
  ::CloseHandle(conn.pipe);
  conn.pipe = INVALID_HANDLE_VALUE;
  if (!passed) {
    *detail = "pending read/write canceled and joined before pipe close";
    return false;
  }
  WireHarness h;
  if (!h.Open(detail))
    return false;
  for (uint32_t id = 1; id <= 4; ++id)
    if (!h.Send(protocol::BuildCreateSessionFrame(h.Header(id, id), LogicalConfig())))
      return false;
  return h.Finish(); // Unread output must not block teardown on a flush.
}
bool PendingAcceptCancellation(std::string *detail) {
  for (bool completed : {false, true}) {
    const std::wstring name = L"\\\\.\\pipe\\v8host-accept-" + std::to_wstring(::GetCurrentProcessId());
    HANDLE pipe = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 0, nullptr);
    OVERLAPPED pending = {};
    pending.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE client = INVALID_HANDLE_VALUE;
    bool ok = pipe != INVALID_HANDLE_VALUE && pending.hEvent &&
        !::ConnectNamedPipe(pipe, &pending) && ::GetLastError() == ERROR_IO_PENDING;
    if (ok && completed) {
      client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
          FILE_FLAG_OVERLAPPED, nullptr);
      ok = client != INVALID_HANDLE_VALUE && ::WaitForSingleObject(pending.hEvent, 3000) == WAIT_OBJECT_0;
    }
    if (ok) {
      const bool connected = V8HostBrokerFinishPendingConnect(pipe, &pending);
      ok = connected == completed;
      if (ok && connected) {
        std::vector<uint8_t> sent{1, 2, 3, 4}, received(4);
        ok = PipeIo(pipe, true, &sent) && PipeIo(client, false, &received) && received == sent;
      }
    } else if (pipe != INVALID_HANDLE_VALUE && pending.hEvent) {
      ::CancelIoEx(pipe, &pending);
      DWORD bytes;
      ::GetOverlappedResult(pipe, &pending, &bytes, TRUE);
    }
    if (client != INVALID_HANDLE_VALUE)
      ::CloseHandle(client);
    if (pending.hEvent)
      ::CloseHandle(pending.hEvent);
    if (pipe != INVALID_HANDLE_VALUE)
      ::CloseHandle(pipe);
    if (!ok) {
      *detail = completed ? "completed accept was discarded during cancellation drain" : "aborted accept was admitted";
      return false;
    }
  }
  return true;
}
bool PendingAcceptPoll(std::string *detail) {
  const std::wstring name = L"\\\\.\\pipe\\v8host-accept-poll-" + std::to_wstring(::GetCurrentProcessId());
  HANDLE pipe = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1, 4096, 4096, 0, nullptr);
  OVERLAPPED pending = {};
  pending.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  bool active = pipe != INVALID_HANDLE_VALUE && pending.hEvent &&
      !::ConnectNamedPipe(pipe, &pending) && ::GetLastError() == ERROR_IO_PENDING;
  bool ok = active;
  // A client can open even after a cancelled accept completes, before pipe close.
  // Ordinary idle polls must leave the original accept pending for that client.
  for (int i = 0; ok && i < 3; ++i)
    ok = V8HostBrokerPollConnect(pipe, &pending, 0) == V8HostBrokerAcceptStatus::kPending;
  HANDLE client = INVALID_HANDLE_VALUE;
  if (ok) {
    client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED, nullptr);
    ok = client != INVALID_HANDLE_VALUE &&
        V8HostBrokerPollConnect(pipe, &pending, 3000) == V8HostBrokerAcceptStatus::kConnected;
    if (ok) {
      active = false;
      std::vector<uint8_t> sent = protocol::BuildHelloFrame(protocol::FrameHeader{}), received(512);
      ok = PipeIo(client, true, &sent) && PipeIo(pipe, false, &received) && received == sent;
    }
  }
  if (active)
    V8HostBrokerFinishPendingConnect(pipe, &pending);
  if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
  if (pending.hEvent) ::CloseHandle(pending.hEvent);
  if (pipe != INVALID_HANDLE_VALUE) ::CloseHandle(pipe);
  if (!ok) *detail = "idle poll discarded the accept before a late client HELLO";
  return ok;
}

bool SharedFanIn(std::string* detail) {
  constexpr size_t kClients = 16;
  std::array<DWORD, kClients> pids = {};
  std::array<uint32_t, kClients> conn_ids = {};
  std::array<bool, kClients> passed = {};
  std::array<std::string, kClients> details;
  std::vector<std::thread> threads;
  for (size_t i = 0; i < kClients; ++i) {
    threads.emplace_back([&, i] {
      BrokerConnection connection;
      HelloResult result;
      passed[i] = ConnectAndHandshake(BrokerMode::kShared,
                                      static_cast<uint32_t>(i + 1), &connection,
                                      &result, &details[i]);
      pids[i] = connection.broker_pid();
      conn_ids[i] = result.conn_id;
    });
  }
  for (std::thread& thread : threads)
    thread.join();
  if (!std::all_of(passed.begin(), passed.end(), [](bool value) {
        return value;
      })) {
    for (size_t i = 0; i < kClients; ++i) {
      if (!passed[i]) {
        *detail = "client " + std::to_string(i) + ": " + details[i];
        break;
      }
    }
    return false;
  }
  std::set<DWORD> unique(pids.begin(), pids.end());
  if (unique.size() != 1 || *unique.begin() == 0) {
    *detail = "clients observed multiple broker PIDs";
    return false;
  }
  // The single shared broker assigns conn_ids monotonically, so every client
  // must have received a distinct one.
  std::set<uint32_t> unique_conn_ids(conn_ids.begin(), conn_ids.end());
  if (unique_conn_ids.size() != kClients) {
    *detail = "broker reused a connection id across fan-in clients";
    return false;
  }
  printf("endpoint fan-in broker pid=%lu clients=%zu\n", *unique.begin(),
         kClients);
  return true;
}

bool ExactPayloadSeparation(std::string* detail) {
  std::vector<uint8_t> sid;
  LUID session = {};
  DWORD error = ERROR_SUCCESS;
  if (!v8host::QueryCurrentSidAndSession(&sid, &session, &error))
    return false;
  std::array<uint8_t, 32> first = {};
  std::array<uint8_t, 32> second = {};
  second[0] = 1;
  std::wstring first_endpoint;
  std::wstring second_endpoint;
  std::array<uint8_t, 32> first_key = {};
  std::array<uint8_t, 32> second_key = {};
  const bool ok =
      v8host::DeriveEndpoint(sid, first, BrokerMode::kShared, nullptr,
                             &first_endpoint, &first_key) &&
      v8host::DeriveEndpoint(sid, second, BrokerMode::kShared, nullptr,
                             &second_endpoint, &second_key) &&
      first_endpoint != second_endpoint;
  if (!ok)
    *detail = "alternate payload digest did not separate endpoint";
  return ok;
}

bool DedicatedUnique(std::string* detail) {
  BrokerConnection first;
  BrokerConnection second;
  HelloResult first_result;
  HelloResult second_result;
  if (!ConnectAndHandshake(BrokerMode::kDedicated, 101, &first, &first_result,
                           detail) ||
      !ConnectAndHandshake(BrokerMode::kDedicated, 102, &second, &second_result,
                           detail))
    return false;
  if (first.endpoint() == second.endpoint() ||
      first.broker_pid() == second.broker_pid()) {
    *detail = "dedicated endpoint or PID reused";
    return false;
  }
  return true;
}

bool MixedMode(std::string* detail) {
  BrokerConnection shared;
  BrokerConnection first;
  BrokerConnection second;
  HelloResult shared_result;
  HelloResult first_result;
  HelloResult second_result;
  if (!ConnectAndHandshake(BrokerMode::kShared, 201, &shared, &shared_result,
                           detail) ||
      !ConnectAndHandshake(BrokerMode::kDedicated, 202, &first, &first_result,
                           detail) ||
      !ConnectAndHandshake(BrokerMode::kDedicated, 203, &second, &second_result,
                           detail))
    return false;
  std::set<DWORD> pids = {shared.broker_pid(), first.broker_pid(),
                          second.broker_pid()};
  if (pids.size() != 3) {
    *detail = "mixed brokers did not isolate PIDs";
    return false;
  }
  return true;
}

bool IdleExitRelaunch(std::string* detail) {
  BrokerConnection connection;
  HelloResult first;
  if (!ConnectAndHandshake(BrokerMode::kShared, 301, &connection, &first,
                           detail))
    return false;
  const DWORD first_pid = connection.broker_pid();
  connection.Close();
  const ULONGLONG start = ::GetTickCount64();
  if (!v8host::test::WaitForProcessExit(first_pid, 8000) ||
      ::GetTickCount64() - start < 4900) {
    *detail = "broker did not honor five-second idle grace";
    return false;
  }
  BrokerConnection replacement;
  HelloResult second;
  if (!ConnectAndHandshake(BrokerMode::kShared, 302, &replacement, &second,
                           detail))
    return false;
  if (first_pid == replacement.broker_pid()) {
    *detail = "broker PID did not change after relaunch";
    return false;
  }
  return true;
}

bool GraceCancel(std::string* detail) {
  BrokerConnection first_connection;
  HelloResult first;
  if (!ConnectAndHandshake(BrokerMode::kShared, 401, &first_connection, &first,
                           detail))
    return false;
  const DWORD first_pid = first_connection.broker_pid();
  first_connection.Close();
  ::Sleep(1500);
  BrokerConnection second_connection;
  HelloResult second;
  if (!ConnectAndHandshake(BrokerMode::kShared, 402, &second_connection, &second,
                           detail))
    return false;
  if (first_pid != second_connection.broker_pid()) {
    *detail = "connection during grace did not preserve broker";
    return false;
  }
  return true;
}

struct SquatterState {
  std::wstring endpoint;
  HANDLE ready = nullptr;
  std::atomic<DWORD> bytes{0};
};

void Squatter(SquatterState* state) {
  HANDLE pipe = ::CreateNamedPipeW(
      state->endpoint.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, 256, 256, 0, nullptr);
  ::SetEvent(state->ready);
  if (pipe == INVALID_HANDLE_VALUE)
    return;
  if (::ConnectNamedPipe(pipe, nullptr) ||
      ::GetLastError() == ERROR_PIPE_CONNECTED) {
    char byte = 0;
    DWORD read = 0;
    if (::ReadFile(pipe, &byte, 1, &read, nullptr))
      state->bytes = read;
  }
  ::CloseHandle(pipe);
}

bool EndpointSquatter(std::string* detail) {
  BrokerRendezvous rendezvous(ExecutableDirectory(), BrokerMode::kShared);
  BrokerConnection warmup;
  const RendezvousStatus init = rendezvous.ConnectOrLaunch(&warmup);
  if (init != RendezvousStatus::kOk)
    return false;
  HelloResult info;
  if (warmup.Handshake(501, &info) != RendezvousStatus::kOk)
    return false;
  const DWORD broker_pid = warmup.broker_pid();
  warmup.Close();
  if (!v8host::test::WaitForProcessExit(broker_pid, 8000))
    return false;

  SquatterState state;
  state.endpoint = rendezvous.endpoint();
  state.ready = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::thread squatter(Squatter, &state);
  ::WaitForSingleObject(state.ready, 2000);
  BrokerConnection connection;
  const RendezvousStatus status = rendezvous.ConnectOrLaunch(&connection);
  if (connection.pipe() != INVALID_HANDLE_VALUE)
    connection.Close();
  squatter.join();
  ::CloseHandle(state.ready);
  const bool ok = status == RendezvousStatus::kPeerAuthenticationFailed &&
                  state.bytes.load() == 0;
  if (!ok)
    *detail = "squatter was not rejected before client write";
  return ok;
}

bool ImmutableWrite(std::string* detail) {
  v8host::HeldFile held;
  DWORD error = ERROR_SUCCESS;
  const std::wstring path = ExecutableDirectory() + L"\\sbox.exe";
  if (!v8host::OpenImmutableFile(path, &held, &error))
    return false;
  HANDLE writer =
      ::CreateFileW(path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (writer != INVALID_HANDLE_VALUE) {
    ::CloseHandle(writer);
    *detail = "write sharing succeeded while immutable handle held";
    return false;
  }
  HANDLE deleter =
      ::CreateFileW(path.c_str(), DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (deleter != INVALID_HANDLE_VALUE) {
    ::CloseHandle(deleter);
    *detail = "delete sharing succeeded while immutable handle held";
    return false;
  }
  return true;
}

bool MutablePreexisting(std::string* detail) {
  const std::wstring path = ExecutableDirectory() + L"\\sbox.exe";
  HANDLE writer =
      ::CreateFileW(path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (writer == INVALID_HANDLE_VALUE) {
    *detail = "could not establish mutable preexisting handle";
    return false;
  }
  v8host::HeldFile held;
  DWORD error = ERROR_SUCCESS;
  const bool rejected = !v8host::OpenImmutableFile(path, &held, &error);
  ::CloseHandle(writer);
  if (!rejected)
    *detail = "immutable open accepted mutable preexisting sharing";
  return rejected;
}

bool PathPolicy(std::string* detail) {
  const bool ok =
      v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                 L"\\\\?\\Volume{a}\\root\\client.exe") &&
      !v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                  L"\\\\?\\Volume{a}\\root2\\client.exe") &&
      !v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                  L"\\\\?\\Volume{b}\\root\\client.exe");
  if (!ok)
    *detail = "component-aware canonical root policy failed";
  return ok;
}

bool DedicatedOwnerExit(std::string* detail) {
  BrokerConnection connection;
  HelloResult result;
  if (!ConnectAndHandshake(BrokerMode::kDedicated, 601, &connection, &result,
                           detail))
    return false;
  const DWORD broker_pid = connection.broker_pid();
  connection.Close();
  if (!v8host::test::WaitForProcessExit(broker_pid, 3000)) {
    *detail = "dedicated broker did not join and exit";
    return false;
  }
  return true;
}

bool DisconnectRaces(std::string* detail) {
  for (uint32_t i = 0; i < 64; ++i) {
    BrokerConnection connection;
    HelloResult result;
    if (!ConnectAndHandshake(BrokerMode::kShared, 700 + i, &connection, &result,
                             detail))
      return false;
    connection.Close();
  }
  return true;
}

bool NoGenericClientRole(std::string* detail) {
  DWORD exit_code = 0;
  const std::wstring command =
      L"\"" + ExecutableDirectory() + L"\\sbox.exe\" --client";
  if (!v8host::test::RunProcess(command, &exit_code) || exit_code != 2) {
    *detail = "generic host accepted removed client role";
    return false;
  }
  return true;
}

bool TrustPolicy(std::string* detail) {
  const bool ok = v8host::TrustAllowed(v8host::TrustStatus::kUnsigned) &&
                  !v8host::TrustAllowed(v8host::TrustStatus::kInvalid) &&
                  !v8host::TrustAllowed(v8host::TrustStatus::kError);
  if (!ok)
    *detail = "development trust policy accepted invalid signature";
  return ok;
}

// ===== peer authentication unit coverage =====
//
// A connected message-mode pipe pair in this process makes the current
// (same-user, trusted, installed) process the authenticated peer. Negative
// cases mutate one policy field, or inject scripted identity facts via
// PeerAuthHooks for the fail-closed paths (PID reread, per-step query failure)
// that a stable local pipe cannot reproduce.
struct SelfPeer {
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE client = INVALID_HANDLE_VALUE;
  v8host::HeldFile image;
  std::vector<uint8_t> sid;
  LUID session = {};
  ~SelfPeer() {
    if (client != INVALID_HANDLE_VALUE)
      ::CloseHandle(client);
    if (server != INVALID_HANDLE_VALUE)
      ::CloseHandle(server);
  }
};

bool MakeSelfPeer(SelfPeer* peer) {
  const std::wstring name = L"\\\\.\\pipe\\v8host-authtest-" +
                            std::to_wstring(::GetCurrentProcessId()) + L"-" +
                            std::to_wstring(::GetTickCount64());
  peer->server = ::CreateNamedPipeW(
      name.c_str(), PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 256, 256, 0,
      nullptr);
  if (peer->server == INVALID_HANDLE_VALUE)
    return false;
  peer->client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                               nullptr, OPEN_EXISTING, 0, nullptr);
  if (peer->client == INVALID_HANDLE_VALUE)
    return false;
  ::ConnectNamedPipe(peer->server, nullptr);
  std::wstring self(32768, L'\0');
  const DWORD n = ::GetModuleFileNameW(nullptr, self.data(),
                                       static_cast<DWORD>(self.size()));
  self.resize(n);
  DWORD error = 0;
  return v8host::OpenImmutableFile(self, &peer->image, &error) &&
         v8host::QueryCurrentSidAndSession(&peer->sid, &peer->session, &error);
}

v8host::PeerAuthPolicy BasePolicy(const SelfPeer& peer, v8host::BrokerMode mode) {
  v8host::PeerAuthPolicy policy = {};
  policy.peer_side = v8host::PeerSide::kPipeClient;
  policy.mode = mode;
  policy.expected_sid = peer.sid;
  policy.expected_session = peer.session;
  policy.install_root = v8host::ParentPath(peer.image.final_path());
  policy.expected_image = &peer.image;
  return policy;
}

bool Authenticates(const SelfPeer& peer,
                   const v8host::PeerAuthPolicy& policy,
                   const v8host::PeerAuthHooks* hooks = nullptr) {
  v8host::HeldProcess out;
  DWORD error = ERROR_SUCCESS;
  return v8host::AuthenticatePipePeer(peer.server, policy, &out, &error, hooks);
}

bool AuthSameUserPositive(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "pipe/identity setup failed";
    return false;
  }
  if (!Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared))) {
    *detail = "correct same-user co-located policy was rejected";
    return false;
  }
  return true;
}

bool AuthCrossUserReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  std::vector<uint8_t> other(SECURITY_MAX_SID_SIZE);
  DWORD size = SECURITY_MAX_SID_SIZE;
  if (!::CreateWellKnownSid(WinWorldSid, nullptr, other.data(), &size)) {
    *detail = "could not build alternate SID";
    return false;
  }
  other.resize(size);
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_sid = other;
  if (Authenticates(peer, policy)) {
    *detail = "different-user SID was accepted";
    return false;
  }
  return true;
}

bool AuthWrongSessionReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_session.LowPart ^= 0x5a5a5a5a;
  if (Authenticates(peer, policy)) {
    *detail = "different logon session was accepted";
    return false;
  }
  return true;
}

bool AuthWrongPayloadImageReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::HeldFile other;
  DWORD error = 0;
  if (!v8host::OpenImmutableFile(ExecutableDirectory() + L"\\v8host.dll", &other,
                                 &error)) {
    *detail = "could not open alternate image";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_image = &other;
  if (Authenticates(peer, policy)) {
    *detail = "wrong expected payload image was accepted";
    return false;
  }
  return true;
}

bool AuthNonColocatedReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.install_root =
      L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\elsewhere";
  if (Authenticates(peer, policy)) {
    *detail = "non-co-located client accepted in shared mode";
    return false;
  }
  return true;
}

bool AuthSiblingPrefixReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.install_root = v8host::ParentPath(peer.image.final_path()) + L"2";
  if (Authenticates(peer, policy)) {
    *detail = "sibling-prefix root accepted as ancestor";
    return false;
  }
  return true;
}

bool AuthDedicatedNonColocatedPositive(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy =
      BasePolicy(peer, v8host::BrokerMode::kDedicated);
  policy.install_root =
      L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\elsewhere";
  if (!Authenticates(peer, policy)) {
    *detail = "dedicated mode rejected a same-user non-co-located peer";
    return false;
  }
  return true;
}

bool AuthLaunchMismatchReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  std::wstring command =
      L"\"" + ExecutableDirectory() + L"\\sbox.exe\" --client";
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process = {};
  if (!::CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &process)) {
    *detail = "could not launch mismatch helper";
    return false;
  }
  ::CloseHandle(process.hThread);
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.launched_process = process.hProcess;
  const bool accepted = Authenticates(peer, policy);
  ::WaitForSingleObject(process.hProcess, 5000);
  ::CloseHandle(process.hProcess);
  if (accepted) {
    *detail = "launch-instance mismatch was accepted";
    return false;
  }
  return true;
}

bool AuthPidRereadMismatchReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  const DWORD real = ::GetCurrentProcessId();
  auto calls = std::make_shared<int>(0);
  v8host::PeerAuthHooks hooks;
  hooks.read_peer_pid = [real, calls](HANDLE, v8host::PeerSide, DWORD* pid) {
    *pid = (++*calls == 1) ? real : real + 1;
    return true;
  };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "peer PID reread mismatch was accepted";
    return false;
  }
  return true;
}

bool AuthQueryFailureReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthHooks hooks;
  hooks.query_identity = [](DWORD, v8host::HeldProcess*, DWORD* error) {
    if (error)
      *error = ERROR_ACCESS_DENIED;
    return false;
  };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "identity query failure was accepted";
    return false;
  }
  return true;
}

bool AuthPidReadFailureReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthHooks hooks;
  hooks.read_peer_pid = [](HANDLE, v8host::PeerSide, DWORD*) { return false; };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "peer PID read failure was accepted";
    return false;
  }
  return true;
}

bool AuthInvalidPipeReject(std::string* detail) {
  v8host::PeerAuthPolicy policy = {};
  policy.peer_side = v8host::PeerSide::kPipeClient;
  policy.mode = v8host::BrokerMode::kShared;
  v8host::HeldProcess out;
  DWORD error = ERROR_SUCCESS;
  if (v8host::AuthenticatePipePeer(INVALID_HANDLE_VALUE, policy, &out, &error)) {
    *detail = "invalid pipe handle authenticated";
    return false;
  }
  return true;
}

// ===== generic-host sbox_broker_api ownership (driven in-broker) =====
//
// Launches the real sbox.exe broker and selects the plugin's dev-only
// sbox_broker_api self-test via an environment variable (no new export). The
// broker exercises argument rejection and the spawn/close/wait ownership cycle
// in-process; "leak" abandons a worker so the generic host's post-run cleanup
// must reclaim it and report the breach (exit 4).
bool RunBrokerApiMode(const wchar_t* mode, DWORD* exit_code) {
  ::SetEnvironmentVariableW(L"V8HOST_BROKER_API_TEST", mode);
  const std::wstring pipe =
      L"\\\\.\\pipe\\v8host-rv1-" + std::wstring(64, L'0');
  const std::wstring command = L"\"" + ExecutableDirectory() +
                               L"\\sbox.exe\" --broker --mode=shared --pipe=" +
                               pipe + L" --plugin v8host.dll";
  const bool ok = v8host::test::RunProcess(command, exit_code);
  ::SetEnvironmentVariableW(L"V8HOST_BROKER_API_TEST", nullptr);
  return ok;
}

bool BrokerApiOwnership(std::string* detail) {
  DWORD code = 0xFFFFFFFF;
  if (!RunBrokerApiMode(L"ownership", &code)) {
    *detail = "ownership broker launch failed";
    return false;
  }
  if (code != 0) {
    *detail = "sbox_broker_api ownership checks failed, exit=" +
              std::to_string(code);
    return false;
  }
  return true;
}

bool BrokerApiLeakedCleanup(std::string* detail) {
  DWORD code = 0xFFFFFFFF;
  if (!RunBrokerApiMode(L"leak", &code)) {
    *detail = "leak broker launch failed";
    return false;
  }
  if (code != 4) {
    *detail = "host did not reclaim leaked worker (expected exit 4), exit=" +
              std::to_string(code);
    return false;
  }
  return true;
}

// Post-verification rename and in-place replacement of a held image must fail
// for the handle's whole lifetime (staged on a throwaway copy, not a live
// binary). Open-for-write and open-for-delete denial are covered by
// immutable-write; this adds the rename and replace mutation variants.
bool ImmutableMutation(std::string* detail) {
  wchar_t temp_dir[MAX_PATH] = {};
  if (!::GetTempPathW(MAX_PATH, temp_dir)) {
    *detail = "temp path query failed";
    return false;
  }
  const std::wstring held_path = std::wstring(temp_dir) + L"v8host-immutable-" +
                                 std::to_wstring(::GetCurrentProcessId()) +
                                 L".bin";
  const std::wstring rename_target = held_path + L".moved";
  if (!::CopyFileW((ExecutableDirectory() + L"\\sbox.exe").c_str(),
                   held_path.c_str(), FALSE)) {
    *detail = "could not stage held file copy";
    return false;
  }
  bool ok = true;
  {
    v8host::HeldFile held;
    DWORD error = 0;
    if (!v8host::OpenImmutableFile(held_path, &held, &error)) {
      ::DeleteFileW(held_path.c_str());
      *detail = "could not open staged copy immutably";
      return false;
    }
    if (::MoveFileExW(held_path.c_str(), rename_target.c_str(),
                      MOVEFILE_REPLACE_EXISTING)) {
      ::MoveFileExW(rename_target.c_str(), held_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING);
      ok = false;
      *detail = "rename succeeded while immutable handle held";
    }
    if (ok) {
      HANDLE replace = ::CreateFileW(
          held_path.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (replace != INVALID_HANDLE_VALUE) {
        ::CloseHandle(replace);
        ok = false;
        *detail = "in-place replace succeeded while immutable handle held";
      }
    }
  }
  ::DeleteFileW(held_path.c_str());
  ::DeleteFileW(rename_target.c_str());
  return ok;
}

// The generic host must reject a resolvable plugin whose vtable reports the
// wrong ABI version / null entries before driving any lifecycle (exit 3).
bool HostRejectsBadPluginAbi(std::string* detail) {
  const std::wstring pipe =
      L"\\\\.\\pipe\\v8host-rv1-" + std::wstring(64, L'0');
  const std::wstring command = L"\"" + ExecutableDirectory() +
                               L"\\sbox.exe\" --broker --mode=shared --pipe=" +
                               pipe + L" --plugin v8host_fake_plugin.dll";
  DWORD code = 0;
  if (!v8host::test::RunProcess(command, &code)) {
    *detail = "bad-plugin broker launch failed";
    return false;
  }
  if (code != 3) {
    *detail =
        "host did not reject invalid plugin ABI (expected exit 3), exit=" +
        std::to_string(code);
    return false;
  }
  return true;
}


struct ContractCClient {
  HMODULE module = nullptr;
  decltype(&v8host_client_initialize) initialize = nullptr;
  decltype(&v8host_client_create_session) create = nullptr;
  decltype(&v8host_client_set_callbacks) callbacks = nullptr;
  decltype(&v8host_client_start_run) start = nullptr;
  decltype(&v8host_client_post_message) post = nullptr;
  decltype(&v8host_client_cancel_run) cancel = nullptr;
  decltype(&v8host_client_close_session) close = nullptr;
  bool Load() {
    if (module) return true;
    const std::wstring path = ExecutableDirectory() + L"/v8host.dll";
    module = ::LoadLibraryExW(path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!module) return false;
#define CLIENT_ENTRY(member, symbol) member = reinterpret_cast<decltype(member)>(::GetProcAddress(module, #symbol)); if (!member) return false
    CLIENT_ENTRY(initialize, v8host_client_initialize);
    CLIENT_ENTRY(create, v8host_client_create_session);
    CLIENT_ENTRY(callbacks, v8host_client_set_callbacks);
    CLIENT_ENTRY(start, v8host_client_start_run);
    CLIENT_ENTRY(post, v8host_client_post_message);
    CLIENT_ENTRY(cancel, v8host_client_cancel_run);
    CLIENT_ENTRY(close, v8host_client_close_session);
#undef CLIENT_ENTRY
    return initialize() == V8HOST_OK;
  }
};
ContractCClient& PublicClient() {
  // The module owns app-thread windows and stays loaded until process exit.
  static ContractCClient client;
  return client;
}
struct PublicCapture {
  ContractCClient* client = nullptr;
  V8HostSession* session = nullptr;
  V8HostRun* run = nullptr;
  DWORD thread = ::GetCurrentThreadId();
  std::vector<int32_t> states, events, kinds;
  std::vector<V8HostStatus> statuses;
  std::vector<std::vector<uint8_t>> messages;
  int terminal = 0, disconnects = 0;
  ULONGLONG startup_started = 0;
  bool valid = true, close_in_terminal = true, closed = false;
  std::function<bool()> observe_worker;
  static void V8HOST_CALL State(void* context, V8HostSession* session, int32_t state, V8HostStatus status) {
    auto& c = *static_cast<PublicCapture*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && session == c.session && status == V8HOST_OK && !c.closed;
    c.states.push_back(state);
    if (state == V8HOST_SESSION_STATE_WORKER_SECURITY_READY && c.startup_started)
      std::printf("[client startup] session=%p duration_ms=%llu\n", session, ::GetTickCount64() - c.startup_started);
  }
  static void V8HOST_CALL Run(void* context, V8HostRun* run, int32_t event, V8HostStatus status) {
    auto& c = *static_cast<PublicCapture*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && run == c.run && !c.closed;
    c.events.push_back(event); c.statuses.push_back(status);
    if (event != V8HOST_RUN_EVENT_STARTED) {
      ++c.terminal;
      if (c.close_in_terminal) {
        c.client->close(c.session); c.closed = true;
      }
    }
  }
  static void V8HOST_CALL Message(void* context, V8HostRun* run, int32_t kind, const void* data, size_t len) {
    auto& c = *static_cast<PublicCapture*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && run == c.run && !c.closed &&
        c.states == std::vector<int32_t>{V8HOST_SESSION_STATE_READY,
          V8HOST_SESSION_STATE_WORKER_STARTUP_READY, V8HOST_SESSION_STATE_WORKER_SECURITY_READY};
    c.kinds.push_back(kind);
    const auto* bytes = static_cast<const uint8_t*>(data);
    c.messages.emplace_back(bytes, bytes + len);
    if (c.observe_worker) c.valid &= c.observe_worker();
  }
  static void V8HOST_CALL Disconnect(void* context) {
    auto& c = *static_cast<PublicCapture*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && !c.closed; ++c.disconnects;
  }
  V8HostCallbacks Table() {
    V8HostCallbacks t = {}; t.struct_size = sizeof(t); t.context = this;
    t.on_session_state = State; t.on_run_event = Run; t.on_relay_message = Message;
    t.on_broker_disconnect = Disconnect; return t;
  }
  ~PublicCapture() { if (session && !closed) client->close(session); }
};
template <class Predicate>
bool PumpPublic(Predicate done) {
  ULONGLONG deadline = ::GetTickCount64() + 10000;
  while (!done()) {
    if (::GetTickCount64() >= deadline) return false;
    MSG msg;
    if (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) ::DispatchMessageW(&msg);
    else ::MsgWaitForMultipleObjectsEx(0, nullptr, 10, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
  }
  return true;
}
// Observe the production-launched dedicated tree before terminal callback close.
struct PublicDedicatedProcesses {
  HANDLE broker = nullptr, worker = nullptr;
  std::wstring shared_endpoint;
  std::string observation_failure;
  bool Prepare() {
    v8host::PayloadIdentity payload;
    std::vector<uint8_t> sid;
    LUID session;
    DWORD error;
    std::array<uint8_t, 32> key;
    return v8host::ResolvePayloadIdentity(ExecutableDirectory(), L"sbox.exe", L"v8host.dll", &payload, &error) &&
        v8host::QueryCurrentSidAndSession(&sid, &session, &error) &&
        v8host::DeriveEndpoint(sid, payload.plugin_set_id, BrokerMode::kShared, nullptr, &shared_endpoint, &key);
  }
  ~PublicDedicatedProcesses() {
    for (HANDLE process : {worker, broker}) {
      if (!process) continue;
      if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0) {
        std::printf("[cleanup] forced owned dedicated process termination\n");
        ::TerminateProcess(process, 1);
        ::WaitForSingleObject(process, 5000);
      }
      ::CloseHandle(process);
    }
  }
  bool Observe() {
    auto fail = [&](const char* why) { observation_failure = why; return false; };
    // A dedicated session must not publish the deterministic shared endpoint.
    if (::WaitNamedPipeW(shared_endpoint.c_str(), 0) || ::GetLastError() != ERROR_FILE_NOT_FOUND)
      return fail("shared endpoint present or unexpected pipe error");
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return fail("process snapshot");
    std::vector<PROCESSENTRY32W> entries;
    PROCESSENTRY32W entry = {}; entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
      do {
        if (::_wcsicmp(entry.szExeFile, L"sbox.exe") == 0) entries.push_back(entry);
      } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    DWORD broker_pid = 0, worker_pid = 0;
    for (const auto& e : entries) {
      if (e.th32ParentProcessID == ::GetCurrentProcessId()) {
        if (broker_pid) return fail("multiple broker children");
        broker_pid = e.th32ProcessID;
      }
    }
    for (const auto& e : entries) {
      if (e.th32ParentProcessID == broker_pid) {
        if (worker_pid) return fail("multiple worker children");
        worker_pid = e.th32ProcessID;
      }
    }
    if (!broker_pid || !worker_pid) return fail("missing broker/worker parent mapping");
    if (broker || worker) {
      const bool alive = broker && worker && ::GetProcessId(broker) == broker_pid &&
          ::GetProcessId(worker) == worker_pid &&
          ::WaitForSingleObject(broker, 0) == WAIT_TIMEOUT &&
          ::WaitForSingleObject(worker, 0) == WAIT_TIMEOUT;
      return alive || fail("held dedicated PID changed/exited");
    }
    HANDLE held_broker = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, broker_pid);
    HANDLE held_worker = ::OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, worker_pid);
    auto same_image = [](HANDLE h) {
      if (!h) return false;
      std::wstring path(32768, L'\0'); DWORD size = static_cast<DWORD>(path.size());
      if (!::QueryFullProcessImageNameW(h, 0, path.data(), &size)) return false;
      path.resize(size);
      return ::_wcsicmp(path.c_str(), (ExecutableDirectory() + L"\\sbox.exe").c_str()) == 0;
    };
    if (!same_image(held_broker) || !same_image(held_worker)) {
      if (held_broker) ::CloseHandle(held_broker);
      if (held_worker) ::CloseHandle(held_worker);
      return fail("held dedicated image mismatch/query");
    }
    broker = held_broker; worker = held_worker;
    std::printf("[public dedicated] broker=%lu worker=%lu\n", broker_pid, worker_pid);
    return true;
  }
  bool Reaped() {
    const bool exited = broker && worker && ::WaitForSingleObject(worker, 10000) == WAIT_OBJECT_0 &&
        ::WaitForSingleObject(broker, 10000) == WAIT_OBJECT_0;
    if (exited) std::printf("[reaped] dedicated broker=%lu worker=%lu\n", ::GetProcessId(broker), ::GetProcessId(worker));
    return exited;
  }
};
bool PublicRealJsMode(int32_t mode, std::string* detail) {
  CapturedBroker broker;
  PublicDedicatedProcesses dedicated;
  if (mode == V8HOST_BROKER_SHARED && !broker.Launch(detail)) return false;
  auto& client = PublicClient();
  if (!client.Load()) { *detail = "production DLL client load/initialize failed"; return false; }
  PublicCapture capture; capture.client = &client; capture.close_in_terminal = false;
  if (mode == V8HOST_BROKER_DEDICATED) {
    if (!dedicated.Prepare()) { *detail = "dedicated shared-endpoint identity"; return false; }
    capture.observe_worker = [&] { return dedicated.Observe(); };
  }
  V8HostSessionConfig config = {}; config.struct_size = sizeof(config);
  config.broker_mode = mode; config.tier = V8HOST_TIER_UNTRUSTED;
  config.prohibit_dynamic_code = 1; config.initial_token = sbox_token_restricted_same_access;
  config.delayed_integrity = sbox_integrity_untrusted;
  if (client.create(&config, &capture.session) != V8HOST_OK || !capture.session) {
    *detail = "public create"; return false;
  }
  auto callbacks = capture.Table();
  if (client.callbacks(capture.session, &callbacks) != V8HOST_OK) {
    *detail = "public callbacks"; return false;
  }
  for (int round = 0; round != 2; ++round) {
    capture.close_in_terminal = round == 1;
    std::string guest = "var n=0;host.onmessage=function(m){if(typeof m==='string'){"
        "host.postMessage('js echo: '+m);}else{var a=new Uint8Array(m);a[0]=0x42;"
        "host.postMessageBinary(m);}if(++n===2)host.complete();};";
    V8HostRunInputs input = {}; input.struct_size = sizeof(input); input.tier_override = -1;
    input.payload = guest.data(); input.payload_len = guest.size();
    char text[6] = {}; std::memcpy(text, round ? "bravo" : "alpha", 5);
    uint8_t binary[] = {0, static_cast<uint8_t>(1 + round * 2), static_cast<uint8_t>(2 + round * 2)};
    V8HostRun* previous = capture.run;
    if (round == 0) capture.startup_started = ::GetTickCount64();
    if (client.start(capture.session, &input, &capture.run) != V8HOST_OK || !capture.run ||
        capture.run == previous) {
      *detail = "public same-session start round=" + std::to_string(round + 1); return false;
    }
    std::fill(guest.begin(), guest.end(), ' ');
    if (client.post(capture.run, sbox_msg_string, text, 5) != V8HOST_OK ||
        client.post(capture.run, sbox_msg_binary, binary, 3) != V8HOST_OK) {
      *detail = "public relay admission"; return false;
    }
    std::memset(text, 'x', 5); std::memset(binary, 0xFF, 3);
    if (!PumpPublic([&] { return capture.terminal >= round + 1 || capture.disconnects; })) {
      for (size_t i = 0; i < capture.events.size(); ++i) std::printf("[failure event] %d status=%d\n", capture.events[i], capture.statuses[i]);
      for (int32_t state : capture.states) std::printf("[failure state] %d\n", state);
      std::printf("[failure callbacks] states=%zu events=%zu messages=%zu terminals=%d disconnects=%d\n", capture.states.size(), capture.events.size(), capture.messages.size(), capture.terminal, capture.disconnects);
      *detail = "public callbacks timed out round=" + std::to_string(round + 1); return false;
    }
    const std::vector<int32_t> events = round == 0
        ? std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED}
        : std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED,
                              V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED};
    const size_t count = static_cast<size_t>(round + 1) * 2;
    if (!capture.valid || capture.terminal != round + 1 || capture.disconnects ||
        capture.states != std::vector<int32_t>{V8HOST_SESSION_STATE_READY,
            V8HOST_SESSION_STATE_WORKER_STARTUP_READY, V8HOST_SESSION_STATE_WORKER_SECURITY_READY} ||
        capture.events != events || capture.statuses != std::vector<V8HostStatus>(count, V8HOST_OK) ||
        capture.kinds.size() != count || capture.messages.size() != count ||
        capture.kinds[count - 2] != sbox_msg_string || capture.kinds[count - 1] != sbox_msg_binary ||
        std::string(capture.messages[count - 2].begin(), capture.messages[count - 2].end()) !=
            (round ? "js echo: bravo" : "js echo: alpha") ||
        capture.messages[count - 1] != std::vector<uint8_t>{0x42, static_cast<uint8_t>(1 + round * 2),
            static_cast<uint8_t>(2 + round * 2)} || capture.closed != (round == 1)) {
      for (size_t i = 0; i < capture.events.size(); ++i) std::printf("[failure event] %d status=%d\n", capture.events[i], capture.statuses[i]);
      for (int32_t state : capture.states) std::printf("[failure state] %d\n", state);
      std::printf("[failure invariant] valid=%d states=%zu events=%zu messages=%zu terminal=%d closed=%d observation=%s\n", capture.valid, capture.states.size(), capture.events.size(), capture.messages.size(), capture.terminal, capture.closed, dedicated.observation_failure.c_str());
      *detail = "public readiness/copy/FIFO/sole terminal invariant round=" + std::to_string(round + 1);
      return false;
    }
  }
  if (!(mode == V8HOST_BROKER_SHARED ? broker.Reaped(1) : dedicated.Reaped())) {
    { std::lock_guard<std::mutex> lock(broker.mutex); std::printf("[failure diagnostics] %s\n", broker.diagnostics.c_str()); }
    *detail = "public held broker/worker reaping"; return false;
  }
  MSG msg; while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) ::DispatchMessageW(&msg);
  *detail = "production DLL: seven client exports; two same-session runs; distinct copied string+binary "
      "JS transforms; readiness/FIFO; one COMPLETED/OK per run; callback close; one worker reaped";
  return capture.valid && capture.terminal == 2 && capture.disconnects == 0;
}
bool PublicRealCancelAndProfileBody(std::string* detail) {
  *detail = "public profile/cancel/admission/reap check";
  CapturedBroker broker;
  if (!broker.Launch(detail)) return false;
  auto& client = PublicClient();
  if (!client.Load()) { *detail = "public client load"; return false; }
  PublicCapture c; c.client = &client; c.close_in_terminal = false;
  V8HostSessionConfig config = {}; config.struct_size = sizeof(config);
  config.broker_mode = V8HOST_BROKER_SHARED; config.tier = V8HOST_TIER_TRUSTED;
  config.initial_token = sbox_token_restricted_same_access; config.delayed_integrity = sbox_integrity_untrusted;
  if (client.create(&config, &c.session) != V8HOST_OK) return false;
  auto callbacks = c.Table(); if (client.callbacks(c.session, &callbacks) != V8HOST_OK) return false;
  DWORD worker_pid = 0;
  auto same_worker = [&] {
    std::lock_guard<std::mutex> lock(broker.mutex);
    if (broker.failed || broker.workers.size() != 1 || ::WaitForSingleObject(broker.workers[0], 0) != WAIT_TIMEOUT) return false;
    const DWORD pid = ::GetProcessId(broker.workers[0]);
    if (!worker_pid) worker_pid = pid;
    return pid && pid == worker_pid;
  };
  for (int round = 0; round < 4; ++round) {
    std::string guest = round == 0 ? "host.onmessage=function(m){};host.postMessage('armed');" :
        "host.postMessage('done');host.complete();";
    V8HostRunInputs input = {}; input.struct_size = sizeof(input); input.tier_override = round == 2 ? V8HOST_TIER_UNTRUSTED : -1;
    input.payload = guest.data(); input.payload_len = guest.size();
    input.engine_dll_override = round == 2 ? L"missing-profile-engine.dll" : L"v8jsisb.dll";
    if (round == 0) c.startup_started = ::GetTickCount64();
    if (client.start(c.session, &input, &c.run) != V8HOST_OK || !c.run) { *detail = "public negative start"; return false; }
    if (round == 0) {
      if (!PumpPublic([&] { return !c.messages.empty() || c.disconnects; }) || c.messages.empty() ||
          std::string(c.messages[0].begin(), c.messages[0].end()) != "armed" ||
          !PumpPublic(same_worker) || client.cancel(c.run) != V8HOST_OK) {
        *detail = "public armed/cancel/worker observation messages=" + std::to_string(c.messages.size()) +
            " terminals=" + std::to_string(c.terminal) + " disconnects=" + std::to_string(c.disconnects) +
            " status=" + std::to_string(c.statuses.empty() ? -1 : c.statuses.back()); return false;
      }
    }
    if (!PumpPublic([&] { return c.terminal >= round + 1 || c.disconnects; })) { *detail = "public negative terminal timeout"; return false; }
    const int32_t expected_event = round == 0 ? V8HOST_RUN_EVENT_CANCELLED : round == 2 ? V8HOST_RUN_EVENT_FAILED : V8HOST_RUN_EVENT_COMPLETED;
    const V8HostStatus expected_status = round == 2 ? V8HOST_E_PROFILE_ALREADY_BOUND : V8HOST_OK;
    const std::vector<int32_t> expected_events = round == 0 ? std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_CANCELLED} :
        round == 1 ? std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_CANCELLED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED} :
        round == 2 ? std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_CANCELLED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_FAILED} :
        std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_CANCELLED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_FAILED, V8HOST_RUN_EVENT_STARTED, V8HOST_RUN_EVENT_COMPLETED};
    if (!c.valid || c.disconnects || c.terminal != round + 1 || c.events != expected_events ||
        c.events.back() != expected_event || c.statuses.back() != expected_status || !same_worker() ||
        client.cancel(c.run) != V8HOST_E_RUN_TERMINAL || client.post(c.run, sbox_msg_string, "late", 4) != V8HOST_E_RUN_TERMINAL) {
      *detail = "public cancel/profile/terminal/reuse round=" + std::to_string(round); return false;
    }
  }
  if (c.messages != std::vector<std::vector<uint8_t>>{{'a','r','m','e','d'}, {'d','o','n','e'}, {'d','o','n','e'}} ||
      c.statuses != std::vector<V8HostStatus>{V8HOST_OK,V8HOST_OK,V8HOST_OK,V8HOST_OK,V8HOST_OK,V8HOST_E_PROFILE_ALREADY_BOUND,V8HOST_OK,V8HOST_OK}) {
    *detail = "profile failure ran guest or wrong terminal status"; return false;
  }
  client.close(c.session); c.closed = true;
  if (!broker.Reaped(1)) { *detail = "public negative worker reaping"; return false; }
  MSG msg; while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) ::DispatchMessageW(&msg);
  return c.valid && c.terminal == 4 && c.disconnects == 0;
}
struct ProcessRunRecord {
  V8HostRun* handle = nullptr;
  std::string token;
  std::vector<int32_t> events, kinds;
  std::vector<V8HostStatus> statuses;
  std::vector<std::vector<uint8_t>> messages;
  unsigned terminals = 0;
};
struct ProcessSessionRecord {
  ContractCClient& client = PublicClient();
  V8HostSession* handle = nullptr;
  DWORD thread = ::GetCurrentThreadId();
  std::deque<ProcessRunRecord> runs;
  std::vector<int32_t> states;
  std::vector<V8HostStatus> state_statuses;
  unsigned disconnects = 0;
  ULONGLONG startup_started = 0;
  bool valid = true, closed = false, close_on_terminal = false;
  ~ProcessSessionRecord() { Close(); }
  void Close() {
    if (handle && !closed) { client.close(handle); closed = true; }
  }
  ProcessRunRecord* Find(V8HostRun* run) {
    valid &= ::GetCurrentThreadId() == thread && !closed;
    for (auto& r : runs) if (r.handle == run) return &r;
    valid = false; return nullptr;
  }
  static void V8HOST_CALL State(void* context, V8HostSession* session, int32_t state, V8HostStatus status) {
    auto& c = *static_cast<ProcessSessionRecord*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && session == c.handle && !c.closed;
    if (c.states.size() >= 8) { c.valid = false; return; }
    c.states.push_back(state); c.state_statuses.push_back(status);
    if (state == V8HOST_SESSION_STATE_WORKER_SECURITY_READY && c.startup_started)
      std::printf("[client startup] session=%p duration_ms=%llu\n", session, ::GetTickCount64() - c.startup_started);
  }
  static void V8HOST_CALL Event(void* context, V8HostRun* run, int32_t event, V8HostStatus status) {
    auto& c = *static_cast<ProcessSessionRecord*>(context);
    auto* r = c.Find(run); if (!r) return;
    if (r->events.size() >= 8) { c.valid = false; return; }
    r->events.push_back(event); r->statuses.push_back(status);
    if (event != V8HOST_RUN_EVENT_STARTED) {
      ++r->terminals; c.valid &= r->terminals == 1;
      std::printf("[terminal] session=%p run=%p token=%s event=%d status=%d count=%u\n",
          c.handle, run, r->token.c_str(), event, status, r->terminals);
      if (c.close_on_terminal) c.Close();
    }
  }
  static void V8HOST_CALL Message(void* context, V8HostRun* run, int32_t kind, const void* data, size_t len) {
    auto& c = *static_cast<ProcessSessionRecord*>(context);
    auto* r = c.Find(run); if (!r) return;
    c.valid &= r->terminals == 0 && c.states == std::vector<int32_t>{V8HOST_SESSION_STATE_READY,
        V8HOST_SESSION_STATE_WORKER_STARTUP_READY, V8HOST_SESSION_STATE_WORKER_SECURITY_READY};
    const auto* bytes = static_cast<const uint8_t*>(data);
    if (r->messages.size() >= 32 || len > 1024) { c.valid = false; return; }
    r->kinds.push_back(kind); r->messages.emplace_back(bytes, bytes + len);
  }
  static void V8HOST_CALL Disconnect(void* context) {
    auto& c = *static_cast<ProcessSessionRecord*>(context);
    c.valid &= ::GetCurrentThreadId() == c.thread && !c.closed;
    ++c.disconnects; c.valid &= c.disconnects == 1;
  }
  bool Create() {
    if (!client.Load()) return false;
    V8HostSessionConfig config = {}; config.struct_size = sizeof(config);
    config.broker_mode = V8HOST_BROKER_SHARED; config.tier = V8HOST_TIER_UNTRUSTED;
    config.prohibit_dynamic_code = 1; config.initial_token = sbox_token_restricted_same_access;
    config.delayed_integrity = sbox_integrity_untrusted;
    if (client.create(&config, &handle) != V8HOST_OK || !handle) return false;
    V8HostCallbacks cb = {}; cb.struct_size = sizeof(cb); cb.context = this;
    cb.on_session_state = State; cb.on_run_event = Event; cb.on_relay_message = Message; cb.on_broker_disconnect = Disconnect;
    return client.callbacks(handle, &cb) == V8HOST_OK;
  }
  bool Start(const std::string& token, bool finish_immediately = false) {
    std::string guest = finish_immediately ? "host.postMessage('" + token + "');host.complete();" :
        "host.onmessage=function(m){if(typeof m==='string'){if(m==='finish'){host.complete();return;}"
        "host.postMessage('" + token + ":'+m);}else{var a=new Uint8Array(m);a[0]^=0x5a;"
        "host.postMessageBinary(m);}};host.postMessage('" + token + ":armed');";
    V8HostRunInputs input = {}; input.struct_size = sizeof(input); input.tier_override = -1;
    input.payload = guest.data(); input.payload_len = guest.size();
    if (runs.empty()) startup_started = ::GetTickCount64();
    runs.emplace_back(); auto& r = runs.back(); r.token = token;
    if (client.start(handle, &input, &r.handle) != V8HOST_OK || !r.handle) { runs.pop_back(); return false; }
    if (std::any_of(runs.begin(), runs.end() - 1, [&](const auto& prior) { return prior.handle == r.handle; })) {
      valid = false; return false;
    }
    return true;
  }
  bool Armed(size_t index) {
    auto& r = runs[index];
    return PumpPublic([&] { return !r.messages.empty() || r.terminals || disconnects; }) && valid &&
        !disconnects && r.events == std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED} && r.terminals == 0 &&
        r.statuses == std::vector<V8HostStatus>{V8HOST_OK} && r.kinds == std::vector<int32_t>{sbox_msg_string} &&
        r.messages == std::vector<std::vector<uint8_t>>{Text(r.token + ":armed")} &&
        state_statuses == std::vector<V8HostStatus>(3, V8HOST_OK);
  }
  static std::vector<uint8_t> Text(const std::string& s) { return {s.begin(), s.end()}; }
  bool Echo(size_t index, const std::string& text, uint8_t value) {
    auto& r = runs[index]; size_t before = r.messages.size();
    uint8_t binary[] = {value, 0, 0xff};
    if (client.post(r.handle, sbox_msg_string, text.data(), text.size()) != V8HOST_OK ||
        client.post(r.handle, sbox_msg_binary, binary, sizeof(binary)) != V8HOST_OK ||
        !PumpPublic([&] { return r.messages.size() >= before + 2 || r.terminals || disconnects; })) return false;
    return valid && !disconnects && !r.terminals && r.messages.size() == before + 2 &&
        r.kinds[before] == sbox_msg_string && r.kinds[before + 1] == sbox_msg_binary &&
        r.messages[before] == Text(r.token + ":" + text) &&
        r.messages[before + 1] == std::vector<uint8_t>{static_cast<uint8_t>(value ^ 0x5a), 0, 0xff};
  }
  bool Terminal(size_t index, int32_t event, V8HostStatus status) {
    auto& r = runs[index];
    return PumpPublic([&] { return r.terminals != 0; }) && valid && r.terminals == 1 &&
        r.events == std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED, event} &&
        r.statuses == std::vector<V8HostStatus>{V8HOST_OK, status};
  }
  bool Finish(size_t index) {
    return client.post(runs[index].handle, sbox_msg_string, "finish", 6) == V8HOST_OK &&
        Terminal(index, V8HOST_RUN_EVENT_COMPLETED, V8HOST_OK);
  }
  size_t CallbackCount() const {
    size_t count = states.size() + disconnects;
    for (const auto& r : runs) count += r.events.size() + r.messages.size();
    return count;
  }
};
void DrainPublic() {
  MSG msg;
  while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) ::DispatchMessageW(&msg);
}
bool MapPublicWorker(CapturedBroker& broker, ProcessSessionRecord& session, size_t index) {
  if (!session.Armed(0) || !broker.Observe(index + 1)) return false;
  HANDLE worker = broker.Worker(index);
  if (!worker || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT) return false;
  std::printf("[mapped] broker=%lu session=%p run=%p ordinal=%zu worker=%lu token=%s\n",
      ::GetProcessId(broker.process), session.handle, session.runs[0].handle, index + 1,
      ::GetProcessId(worker), session.runs[0].token.c_str());
  return true;
}
bool PublicNSessionBody(std::string* detail) {
  *detail = "session/PID/routing/reap check";
  CapturedBroker broker;
  if (!broker.Launch(detail)) return false;
  std::array<ProcessSessionRecord, 3> sessions;
  for (size_t i = 0; i < sessions.size(); ++i) {
    if (!sessions[i].Create() || !sessions[i].Start("tenant" + std::to_string(i)) ||
        !MapPublicWorker(broker, sessions[i], i)) { *detail = "sequential session/PID/armed mapping"; return false; }
  }
  std::set<DWORD> pids;
  for (size_t i = 0; i < sessions.size(); ++i) {
    HANDLE h = broker.Worker(i);
    if (!h || ::WaitForSingleObject(h, 0) != WAIT_TIMEOUT || !pids.insert(::GetProcessId(h)).second) return false;
  }
  for (size_t round = 0; round < 2; ++round) {
    for (size_t i = 0; i < sessions.size(); ++i) {
      auto& c = sessions[i];
      if (round && (!c.Start("reuse" + std::to_string(i)) || !c.Armed(round))) return false;
      if (!c.Echo(round, "unique" + std::to_string(i + round * 3), static_cast<uint8_t>(i + round * 16)) ||
          !c.Finish(round) || !broker.Observe(3) || ::WaitForSingleObject(broker.Worker(i), 0) != WAIT_TIMEOUT ||
          !pids.count(::GetProcessId(broker.Worker(i)))) { *detail = "text/binary routing/reuse"; return false; }
    }
  }
  for (auto& c : sessions) c.Close();
  if (!broker.Reaped(3)) return false;
  DrainPublic();
  for (auto& c : sessions) if (!c.valid || c.disconnects || c.runs.size() != 2 ||
      c.runs[0].messages.size() != 3 || c.runs[1].messages.size() != 3) return false;
  *detail = "3 live sessions/3 distinct held PIDs; per-run text+binary tokens; 2 runs/PID; all reaped";
  return true;
}
bool PublicWorkerExitBody(std::string* detail) {
  *detail = "worker-exit admission/fault/survival/reap check";
  CapturedBroker broker;
  if (!broker.Launch(detail)) return false;
  ProcessSessionRecord crashed, sibling;
  if (!crashed.Create() || !crashed.Start("completed") || !MapPublicWorker(broker, crashed, 0) || !crashed.Finish(0) ||
      !sibling.Create() || !sibling.Start("survivor") || !MapPublicWorker(broker, sibling, 1) ||
      !crashed.Start("crashed-active") || !crashed.Armed(1) || !crashed.Start("crashed-pending") ||
      !PumpPublic([&] { return !crashed.runs[2].events.empty(); })) return false;
  if (crashed.runs[2].events != std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED} ||
      !crashed.runs[2].messages.empty() || crashed.runs[2].terminals) return false;
  HANDLE killed = broker.Worker(0), healthy = broker.Worker(1);
  if (!killed || !healthy || ::WaitForSingleObject(killed, 0) != WAIT_TIMEOUT ||
      !::TerminateProcess(killed, 0xfa17) || ::WaitForSingleObject(killed, 10000) != WAIT_OBJECT_0) return false;
  DWORD code = 0;
  if (!::GetExitCodeProcess(killed, &code) || code != 0xfa17) return false;
  std::printf("[fault] broker=%lu worker=%lu exit=%lu owned-handle\n",
      ::GetProcessId(broker.process), ::GetProcessId(killed), code);
  if (!crashed.Terminal(1, V8HOST_RUN_EVENT_WORKER_EXITED, V8HOST_E_RUN_TERMINAL) ||
      !crashed.Terminal(2, V8HOST_RUN_EVENT_WORKER_EXITED, V8HOST_E_RUN_TERMINAL) ||
      !crashed.runs[2].messages.empty() || crashed.runs[0].terminals != 1 ||
      crashed.runs[0].events.back() != V8HOST_RUN_EVENT_COMPLETED || crashed.disconnects) {
    *detail = "completed/active/queued worker-exit arbitration"; return false;
  }
  for (size_t i : {size_t{1}, size_t{2}}) {
    if (crashed.client.post(crashed.runs[i].handle, sbox_msg_string, "late", 4) != V8HOST_E_RUN_TERMINAL ||
        crashed.client.cancel(crashed.runs[i].handle) != V8HOST_E_RUN_TERMINAL) return false;
  }
  crashed.Close(); size_t frozen = crashed.CallbackCount();
  if (::WaitForSingleObject(broker.process, 0) != WAIT_TIMEOUT ||
      ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT || !sibling.Echo(0, "after-kill", 0x11) ||
      !sibling.Finish(0) || !sibling.Start("survivor-fresh") || !sibling.Armed(1) ||
      !sibling.Echo(1, "fresh-after-kill", 0x22) || !sibling.Finish(1) || !broker.Observe(2) ||
      ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT) { *detail = "original sibling worker did not survive"; return false; }
  sibling.Close();
  if (!broker.Reaped(2)) return false;
  DrainPublic();
  *detail = "OS-forced recorded worker exit; completed winner retained; active+queued WORKER_EXITED once; sibling original PID survives";
  return crashed.valid && sibling.valid && crashed.CallbackCount() == frozen && !sibling.disconnects;
}
bool PublicDisconnectBody(std::string* detail) {
  *detail = "disconnect admission/order/survival/reap check";
  CapturedBroker broker;
  if (!broker.Launch(detail)) return false;
  ProcessSessionRecord sibling;
  if (!sibling.Create() || !sibling.Start("disconnect-survivor") || !MapPublicWorker(broker, sibling, 0)) return false;
  HANDLE healthy = broker.Worker(0);
  std::array<ProcessSessionRecord, 4> closed_sessions;
  for (size_t order = 0; order < closed_sessions.size(); ++order) {
    auto& c = closed_sessions[order];
    if (!c.Create() || !c.Start("close-order" + std::to_string(order)) || !MapPublicWorker(broker, c, order + 1)) return false;
    if (order == 0) {
      // Close the real transport before either active or queued guest completion.
      if (!c.Start("never-execute") || !PumpPublic([&] { return !c.runs[1].events.empty(); }) ||
          !c.runs[1].messages.empty()) return false;
      c.Close();
    } else if (order == 1) {
      if (!c.Finish(0)) return false;
      c.Close();
    } else if (order == 2) {
      c.close_on_terminal = true;
      if (!c.Finish(0) || !c.closed) return false;
    } else {
      // Completion may race EOF, but explicit close suppresses queued delivery.
      if (c.client.post(c.runs[0].handle, sbox_msg_string, "finish", 6) != V8HOST_OK) return false;
      c.Close();
    }
    size_t frozen = c.CallbackCount();
    HANDLE worker = broker.Worker(order + 1);
    if (!worker || ::WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0 ||
        ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT || ::WaitForSingleObject(broker.process, 0) != WAIT_TIMEOUT ||
        !sibling.Echo(0, "close-survived" + std::to_string(order), static_cast<uint8_t>(order))) return false;
    DrainPublic();
    if (!c.valid || c.CallbackCount() != frozen || c.disconnects || c.runs[0].messages.size() != 1 ||
        c.runs[0].terminals != ((order == 1 || order == 2) ? 1u : 0u) ||
        (order == 0 && (c.runs[1].terminals || !c.runs[1].messages.empty()))) {
      *detail = "close/EOF/completion/callback-close ordering=" + std::to_string(order); return false;
    }
    std::printf("[reaped] close-order=%zu broker=%lu session=%p worker=%lu callbacks=%zu\n",
        order, ::GetProcessId(broker.process), c.handle, ::GetProcessId(worker), frozen);
  }
  if (!sibling.Finish(0) || !sibling.Start("disconnect-fresh") || !sibling.Armed(1) ||
      !sibling.Echo(1, "fresh", 0x33) || !sibling.Finish(1) || !broker.Observe(5) ||
      ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT) return false;
  sibling.Close();
  if (!broker.Reaped(5)) return false;
  DrainPublic();
  *detail = "real pipe EOF before/after completion, callback-close, completion/EOF overlap; no callback after close; original sibling PID survives";
  return sibling.valid && !sibling.disconnects;
}
bool PublicBrokerKillBody(std::string* detail) {
  *detail = "broker-loss admission/terminal/replacement check";
  CapturedBroker old_broker;
  if (!old_broker.Launch(detail)) return false;
  std::array<ProcessSessionRecord, 3> old;
  for (size_t i = 0; i < old.size(); ++i) {
    auto& c = old[i];
    if (!c.Create() || !c.Start("old-active" + std::to_string(i)) || !MapPublicWorker(old_broker, c, i) ||
        !c.Start("old-queued-side-effect" + std::to_string(i)) ||
        !PumpPublic([&] { return !c.runs[1].events.empty(); }) ||
        c.runs[1].events != std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED} ||
        !c.runs[1].messages.empty() || c.runs[1].terminals) return false;
  }
  DWORD pid = ::GetProcessId(old_broker.process);
  if (!::TerminateProcess(old_broker.process, 0xbeef) || !old_broker.ReapedAfterKill(3)) {
    *detail = "owned broker kill did not reap every held worker"; return false;
  }
  std::printf("[fault] owned broker=%lu killed; every old worker exited before replacement\n", pid);
  for (auto& c : old) {
    for (size_t i = 0; i < c.runs.size(); ++i) {
      if (!c.Terminal(i, V8HOST_RUN_EVENT_BROKER_LOST, V8HOST_E_BROKER_LOST) ||
          c.client.post(c.runs[i].handle, sbox_msg_string, "old-late", 8) != V8HOST_E_RUN_TERMINAL ||
          c.client.cancel(c.runs[i].handle) != V8HOST_E_RUN_TERMINAL) return false;
    }
    if (!PumpPublic([&] { return c.disconnects != 0; }) || !c.valid || c.disconnects != 1 ||
        c.states.back() != V8HOST_SESSION_STATE_CLOSED || c.state_statuses.back() != V8HOST_E_BROKER_LOST ||
        c.runs[0].messages.size() != 1 || !c.runs[1].messages.empty()) return false;
  }
  CapturedBroker replacement;
  WireHarness observer;
  if (!replacement.Launch(detail) ||
      !ConnectAndHandshake(BrokerMode::kShared, 900, &observer.connection, &observer.hello, detail) ||
      observer.connection.broker_pid() != ::GetProcessId(replacement.process)) return false;
  auto fence = [&](uint32_t request) {
    return observer.Send(protocol::BuildCancelRunFrame(observer.Header(request, 1, 1))) &&
        observer.Expect(protocol::MessageType::ACK, request, 1, 1);
  };
  if (!fence(1)) return false;
  for (auto& c : old) {
    std::string guest = "host.postMessage('old-retry-side-effect');host.complete();";
    V8HostRunInputs input = {}; input.struct_size = sizeof(input); input.tier_override = -1;
    input.payload = guest.data(); input.payload_len = guest.size();
    V8HostRun* run = nullptr;
    if (c.client.start(c.handle, &input, &run) != V8HOST_E_CONNECT || run ||
        c.client.post(c.runs[0].handle, sbox_msg_string, "old", 3) != V8HOST_E_RUN_TERMINAL) {
      *detail = "old terminal session/run accepted replay"; return false;
    }
  }
  if (!fence(2)) return false;
  {
    std::lock_guard<std::mutex> lock(replacement.mutex);
    if (replacement.failed || !replacement.workers.empty()) { *detail = "replacement automatic creation"; return false; }
  }
  std::printf("[replacement] broker=%lu workers=0 authenticated observer; old retries rejected\n",
      ::GetProcessId(replacement.process));
  ProcessSessionRecord fresh;
  if (!fresh.Create() || !fresh.Start("fresh-only") || !MapPublicWorker(replacement, fresh, 0) ||
      !fresh.Echo(0, "new-token", 0x44) || !fresh.Finish(0) || !fence(3)) return false;
  for (auto& c : old) {
    if (!c.valid || c.disconnects != 1 || c.runs[0].terminals != 1 || c.runs[1].terminals != 1 ||
        c.runs[0].messages != std::vector<std::vector<uint8_t>>{ProcessSessionRecord::Text(c.runs[0].token + ":armed")} ||
        !c.runs[1].messages.empty()) return false;
    c.Close();
  }
  fresh.Close(); observer.connection.Close();
  if (!replacement.Reaped(1)) { *detail = "replacement extra creation or failed reap"; return false; }
  DrainPublic();
  *detail = "3 old workers reaped before same-set replacement; 6 BROKER_LOST once; zero automatic workers; old attempts rejected; only explicit fresh token/one worker";
  return fresh.valid && !fresh.disconnects && fresh.runs[0].terminals == 1 &&
      std::all_of(old.begin(), old.end(), [](const auto& c) { return c.valid; });
}
// Two sibling sessions share one authenticated connection; the third uses another.
bool SameConnectionWorkerExitBody(std::string* detail) {
  CapturedBroker broker;
  WireHarness siblings, other;
  *detail = "same-connection setup/admission";
  if (!OpenCaptured(broker, siblings, detail) ||
      !ConnectAndHandshake(BrokerMode::kShared, 900, &other.connection, &other.hello, detail) ||
      other.connection.broker_pid() != ::GetProcessId(broker.process) ||
      other.hello.conn_id == siblings.hello.conn_id) return false;
  auto config = LogicalConfig(); config.broker_mode = 1;
  config.initial_token = sbox_token_restricted_same_access; config.delayed_integrity = sbox_integrity_untrusted;
  if (!siblings.Send(protocol::BuildCreateSessionFrame(siblings.Header(2, 2), config)) ||
      !siblings.Expect(protocol::MessageType::ACK, 2, 2) || !siblings.Expect(protocol::MessageType::SESSION_READY, 0, 2) ||
      !other.Send(protocol::BuildCreateSessionFrame(other.Header(1), config)) ||
      !other.Expect(protocol::MessageType::ACK, 1, 1) || !other.Expect(protocol::MessageType::SESSION_READY, 0, 1)) return false;
  auto relay = [&](WireHarness& h, uint32_t session, uint32_t run, int32_t kind, const std::vector<uint8_t>& body) {
    auto header = h.Header(0, session, run); header.type = protocol::MessageType::RELAY_TO_WORKER;
    return h.Send(protocol::BuildRelayFrame(header, kind, body.data(), body.size()));
  };
  auto text = [&](WireHarness& h, uint32_t session, uint32_t run, const std::string& body) {
    return relay(h, session, run, sbox_msg_string, {body.begin(), body.end()});
  };
  auto message = [&](WireHarness& h, uint32_t session, uint32_t run, int32_t kind, const std::vector<uint8_t>& expected) {
    std::vector<uint8_t> bytes; protocol::FrameHeader header; int32_t received_kind;
    const uint8_t* body; size_t size;
    return h.Receive(&bytes, &header) && header.type == protocol::MessageType::RELAY_FROM_WORKER &&
        header.conn_id == h.hello.conn_id && header.session_id == session && header.run_id == run && !header.request_id &&
        protocol::DecodeRelayPayload(bytes.data() + protocol::kFrameHeaderSize,
            bytes.size() - protocol::kFrameHeaderSize, &received_kind, &body, &size) && received_kind == kind &&
        std::vector<uint8_t>(body, body + size) == expected;
  };
  auto token = [&](WireHarness& h, uint32_t session, uint32_t run, const std::string& expected) {
    return message(h, session, run, sbox_msg_string, {expected.begin(), expected.end()});
  };
  auto start = [&](WireHarness& h, uint32_t request, uint32_t session, uint32_t run, const std::string& tag, bool first) {
    const std::string guest = "host.onmessage=function(m){if(typeof m==='string'){if(m==='finish'){host.complete();return;}"
        "host.postMessage('" + tag + ":'+m);}else{var a=new Uint8Array(m);a[0]^=0x5a;host.postMessageBinary(m);}};"
        "host.postMessage('" + tag + ":armed');";
    return h.Send(protocol::BuildStartRunFrame(h.Header(request, session, run), Script(guest))) &&
        h.Expect(protocol::MessageType::ACK, request, session, run) &&
        (!first || (h.Expect(protocol::MessageType::STARTUP_READY, 0, session) &&
            h.Expect(protocol::MessageType::SECURITY_READY, 0, session))) && token(h, session, run, tag + ":armed");
  };
  auto finish = [&](WireHarness& h, uint32_t session, uint32_t run) {
    std::vector<uint8_t> bytes; protocol::FrameHeader header; protocol::ResultPayload result;
    const bool ok = text(h, session, run, "finish") && h.Receive(&bytes, &header) &&
        header.type == protocol::MessageType::RESULT && header.conn_id == h.hello.conn_id &&
        header.session_id == session && header.run_id == run && !header.request_id &&
        protocol::DecodeResultPayload(bytes.data() + protocol::kFrameHeaderSize,
            bytes.size() - protocol::kFrameHeaderSize, &result) && result.disposition == protocol::ResultDisposition::kCompleted;
    if (ok) std::printf("[terminal] wire conn=%u session=%u run=%u COMPLETED count=1\n", h.hello.conn_id, session, run);
    return ok;
  };
  std::array<WireHarness*, 3> connections{&siblings, &siblings, &other};
  std::array<uint32_t, 3> ids{1, 2, 1}, requests{3, 4, 2};
  std::set<DWORD> pids;
  for (size_t i = 0; i < 3; ++i) {
    auto& h = *connections[i];
    if (!start(h, requests[i], ids[i], 1, "wire" + std::to_string(i), true) || !broker.Observe(i + 1)) return false;
    HANDLE worker = broker.Worker(i);
    if (!worker || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT || !pids.insert(::GetProcessId(worker)).second) return false;
    std::printf("[mapped] broker=%lu conn=%u session=%u run=1 ordinal=%zu worker=%lu\n",
        ::GetProcessId(broker.process), h.hello.conn_id, ids[i], i + 1, ::GetProcessId(worker));
  }
  *detail = "same-connection exact text/binary routing and two runs/original PID";
  for (size_t round = 0; round < 2; ++round) for (size_t i = 0; i < 3; ++i) {
    auto& h = *connections[i]; const uint32_t run = static_cast<uint32_t>(round + 1);
    const std::string tag = "wire" + std::to_string(i) + (round ? "-reuse" : "");
    if (round && !start(h, i == 2 ? 3 : static_cast<uint32_t>(5 + i), ids[i], run, tag, false)) return false;
    const std::string sent = "unique" + std::to_string(i + round * 3);
    const uint8_t value = static_cast<uint8_t>(i + round * 16);
    if (!text(h, ids[i], run, sent) || !token(h, ids[i], run, tag + ":" + sent) ||
        !relay(h, ids[i], run, sbox_msg_binary, {value, 0, 0xff}) ||
        !message(h, ids[i], run, sbox_msg_binary, {static_cast<uint8_t>(value ^ 0x5a), 0, 0xff}) ||
        !finish(h, ids[i], run) || !broker.Observe(3) || ::WaitForSingleObject(broker.Worker(i), 0) != WAIT_TIMEOUT) return false;
  }
  *detail = "same-connection worker fault/active+queued terminal";
  if (!start(siblings, 7, 1, 3, "crashed", false) ||
      !siblings.Send(protocol::BuildStartRunFrame(siblings.Header(8, 1, 4), Script("host.postMessage('never');host.complete();"))) ||
      !siblings.Expect(protocol::MessageType::ACK, 8, 1, 4) ||
      !start(siblings, 9, 2, 3, "sibling", false) || !start(other, 4, 1, 3, "other", false)) return false;
  HANDLE killed = broker.Worker(0); DWORD code = 0;
  if (!::TerminateProcess(killed, 0xfa17) || ::WaitForSingleObject(killed, 10000) != WAIT_OBJECT_0 ||
      !::GetExitCodeProcess(killed, &code) || code != 0xfa17 ||
      !siblings.Expect(protocol::MessageType::WORKER_EXIT, 0, 1)) return false;
  std::printf("[fault] broker=%lu worker=%lu exit=%lu; wire conn=%u session=1 runs=3,4 WORKER_EXIT count=1\n",
      ::GetProcessId(broker.process), ::GetProcessId(killed), code, siblings.hello.conn_id);
  // The received terminal fences worker retirement. Late relays are dropped;
  // CANCEL/CLOSE are idempotent ACKs, and START on the removed session is BAD_STATE.
  *detail = "late RELAY/CANCEL/START/CLOSE responses or duplicate terminal";
  if (!text(siblings, 1, 3, "late") || !text(siblings, 1, 4, "late") ||
      !siblings.Send(protocol::BuildCancelRunFrame(siblings.Header(10, 1, 3))) ||
      !siblings.Expect(protocol::MessageType::ACK, 10, 1, 3) ||
      !siblings.Send(protocol::BuildCancelRunFrame(siblings.Header(11, 1, 4))) ||
      !siblings.Expect(protocol::MessageType::ACK, 11, 1, 4) ||
      !siblings.Send(protocol::BuildStartRunFrame(siblings.Header(12, 1, 5), Script("host.complete();")))) return false;
  std::vector<uint8_t> bytes; protocol::FrameHeader header; protocol::ErrorPayload error;
  if (!siblings.Receive(&bytes, &header) || header.type != protocol::MessageType::ERROR ||
      header.conn_id != siblings.hello.conn_id || header.session_id != 1 || header.run_id != 5 || header.request_id != 12 ||
      !protocol::DecodeErrorPayload(bytes.data() + protocol::kFrameHeaderSize, bytes.size() - protocol::kFrameHeaderSize, &error) ||
      error.status_code != protocol::StatusCode::ERROR_BAD_STATE ||
      !siblings.Send(protocol::BuildCloseSessionFrame(siblings.Header(13, 1))) ||
      !siblings.Expect(protocol::MessageType::ACK, 13, 1) ||
      !siblings.Send(protocol::BuildCloseSessionFrame(siblings.Header(14, 1))) ||
      !siblings.Expect(protocol::MessageType::ACK, 14, 1)) return false;
  *detail = "original same-connection sibling and independent connection survival";
  for (size_t i : {size_t{1}, size_t{2}}) {
    auto& h = *connections[i]; const std::string tag = i == 1 ? "sibling" : "other";
    if (!text(h, ids[i], 3, "after-kill") || !token(h, ids[i], 3, tag + ":after-kill") || !finish(h, ids[i], 3) ||
        !start(h, i == 1 ? 15 : 5, ids[i], 4, "fresh" + tag, false) ||
        !text(h, ids[i], 4, "fresh") || !token(h, ids[i], 4, "fresh" + tag + ":fresh") || !finish(h, ids[i], 4) ||
        !broker.Observe(3) || ::WaitForSingleObject(broker.Worker(i), 0) != WAIT_TIMEOUT ||
        ::WaitForSingleObject(broker.process, 0) != WAIT_TIMEOUT) return false;
  }
  // Final control barriers reject any queued second terminal/late output.
  if (!siblings.Send(protocol::BuildCloseSessionFrame(siblings.Header(16, 2))) ||
      !siblings.Expect(protocol::MessageType::ACK, 16, 2) ||
      !other.Send(protocol::BuildCloseSessionFrame(other.Header(6))) || !other.Expect(protocol::MessageType::ACK, 6, 1)) return false;
  siblings.connection.Close(); other.connection.Close();
  if (!broker.Reaped(3)) { *detail = "same-connection joined reaping"; return false; }
  *detail = "3 real PIDs/2 connections including siblings; text/binary and reuse; killed session only; deterministic late-frame barriers";
  return true;
}
// Each child loads its own production client singleton and immutable payload set.
// These helpers retain the negotiated addressing and distinguish EOF from timeout.
bool ProcessToken(WireHarness& h, uint32_t session, uint32_t run, const std::string& expected) {
  std::vector<uint8_t> bytes; protocol::FrameHeader header; int32_t kind;
  const uint8_t* body; size_t size;
  return h.Receive(&bytes, &header) && header.type == protocol::MessageType::RELAY_FROM_WORKER &&
      header.conn_id == h.hello.conn_id && header.session_id == session && header.run_id == run && !header.request_id &&
      header.version_major == h.hello.selected_major && header.version_minor == h.hello.selected_minor &&
      protocol::DecodeRelayPayload(bytes.data() + protocol::kFrameHeaderSize,
          bytes.size() - protocol::kFrameHeaderSize, &kind, &body, &size) && kind == sbox_msg_string &&
      std::string(reinterpret_cast<const char*>(body), size) == expected;
}
bool ProcessEof(WireHarness& h) {
  OVERLAPPED pending = {}; pending.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!pending.hEvent) return false;
  std::vector<uint8_t> bytes(protocol::kMaxFrameSize); DWORD size = 0;
  const BOOL started = ::ReadFile(h.connection.pipe(), bytes.data(), static_cast<DWORD>(bytes.size()), nullptr, &pending);
  DWORD error = started ? ERROR_SUCCESS : ::GetLastError();
  if (started || error == ERROR_IO_PENDING) {
    if (::WaitForSingleObject(pending.hEvent, 10000) == WAIT_OBJECT_0)
      error = ::GetOverlappedResult(h.connection.pipe(), &pending, &size, FALSE) ? ERROR_SUCCESS : ::GetLastError();
    else {
      ::CancelIoEx(h.connection.pipe(), &pending);
      ::GetOverlappedResult(h.connection.pipe(), &pending, &size, TRUE);
      error = WAIT_TIMEOUT;
    }
  }
  ::CloseHandle(pending.hEvent);
  return error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED;
}
protocol::CreateSessionPayload ProcessConfig() {
  auto config = LogicalConfig(); config.broker_mode = 1;
  config.initial_token = sbox_token_restricted_same_access; config.delayed_integrity = sbox_integrity_untrusted;
  return config;
}
bool ProcessCreate(WireHarness& h, uint32_t request, uint32_t session) {
  return h.Send(protocol::BuildCreateSessionFrame(h.Header(request, session), ProcessConfig())) &&
      h.Expect(protocol::MessageType::ACK, request, session) && h.Expect(protocol::MessageType::SESSION_READY, 0, session);
}
bool ProcessStart(WireHarness& h, uint32_t request, uint32_t session, uint32_t run, bool first) {
  return h.Send(protocol::BuildStartRunFrame(h.Header(request, session, run), Script(
      "host.onmessage=function(m){host.postMessage(m);};host.postMessage('armed');"))) &&
      h.Expect(protocol::MessageType::ACK, request, session, run) &&
      (!first || (h.Expect(protocol::MessageType::STARTUP_READY, 0, session) &&
          h.Expect(protocol::MessageType::SECURITY_READY, 0, session))) && ProcessToken(h, session, run, "armed");
}
bool ProcessEcho(WireHarness& h, uint32_t session, uint32_t run, const std::string& text) {
  auto header = h.Header(0, session, run); header.type = protocol::MessageType::RELAY_TO_WORKER;
  return h.Send(protocol::BuildRelayFrame(header, sbox_msg_string,
      reinterpret_cast<const uint8_t*>(text.data()), text.size())) && ProcessToken(h, session, run, text);
}
bool FillProcessInbound(WireHarness& h, uint32_t session, uint32_t run, size_t bytes, size_t* charged) {
  const size_t overhead = v8host::EncodeRunEnvelope(GuestRelay(0, run)).size();
  size_t frames = 0;
  if (overhead != 16 || bytes > protocol::kMaxQueuedRelayBytesPerRun) return false;
  while (bytes) {
    size_t part = (std::min)(bytes, size_t(protocol::kMaxFramePayload));
    // Avoid an unencodable tail without exceeding the legal per-frame envelope.
    if (bytes > part && bytes - part < overhead) part -= overhead;
    if (part < overhead || ++frames > 256) return false;
    std::vector<uint8_t> payload(part - overhead, 7);
    auto header = h.Header(0, session, run); header.type = protocol::MessageType::RELAY_TO_WORKER;
    auto frame = protocol::BuildRelayFrame(header, sbox_msg_binary, payload.data(), payload.size());
    if (frame.size() > protocol::kMaxFrameSize || !h.Send(std::move(frame))) return false;
    *charged += v8host::EncodeRunEnvelope(GuestRelay(payload.size(), run)).size();
    bytes -= part;
  }
  return true;
}
bool RealInboundAggregateBody(std::string* detail) {
  CapturedBroker broker; WireHarness healthy;
  *detail = "aggregate healthy-connection setup";
  if (!OpenCaptured(broker, healthy, detail) || !ProcessStart(healthy, 2, 1, 1, true) || !broker.Observe(1)) return false;
  HANDLE survivor = broker.Worker(0); size_t count = 1;
  const size_t cap = protocol::kMaxQueuedRelayBytesPerConnection;
  // Separate legal histories prove cap-1, cap, and an encoded envelope exceeding cap by exactly one.
  for (unsigned variant = 0; variant < 4; ++variant) {
    WireHarness pressured;
    *detail = "aggregate authenticated admission variant=" + std::to_string(variant);
    if (!ConnectAndHandshake(BrokerMode::kShared, 900, &pressured.connection, &pressured.hello, detail) ||
        pressured.connection.broker_pid() != ::GetProcessId(broker.process) || pressured.hello.conn_id == healthy.hello.conn_id)
      return false;
    uint32_t request = 1; const size_t first = count;
    for (uint32_t session = 1; session <= 6; ++session) {
      if (!ProcessCreate(pressured, request++, session) || !ProcessStart(pressured, request++, session, 1, true) ||
          !broker.Observe(++count)) return false;
      HANDLE worker = broker.Worker(count - 1);
      if (!worker || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT) return false;
      std::printf("[mapped] broker=%lu conn=%u session=%u run=1 worker=%lu\n",
          ::GetProcessId(broker.process), pressured.hello.conn_id, session, ::GetProcessId(worker));
      for (uint32_t run = 2; run <= 4 && !(session == 6 && run == 4); ++run) {
        const uint32_t admitted = request++;
        if (!pressured.Send(protocol::BuildStartRunFrame(pressured.Header(admitted, session, run), Script(
                "host.postMessage('pending-executed');host.complete();"))) ||
            !pressured.Expect(protocol::MessageType::ACK, admitted, session, run)) return false;
      }
    }
    const size_t cap_bytes = variant == 0 ? cap - 1 : variant == 1 ? cap : cap - 15;
    size_t charged = 0;
    for (unsigned pending = 0; pending < 17; ++pending) {
      const uint32_t session = pending / 3 + 1, run = pending % 3 + 2;
      const size_t bytes = pending < 15 ? protocol::kMaxQueuedRelayBytesPerRun :
          pending == 15 ? protocol::kMaxQueuedRelayBytesPerRun - 100 : cap_bytes - (cap - 100);
      if (!FillProcessInbound(pressured, session, run, bytes, &charged)) return false;
    }
    *detail = "aggregate boundary/control fence variant=" + std::to_string(variant);
    if (charged != cap_bytes || !pressured.Send(protocol::BuildCancelRunFrame(pressured.Header(request, 1, 99))) ||
        !pressured.Expect(protocol::MessageType::ACK, request++, 1, 99)) return false;
    std::printf("[pressure] conn=%u bytes=%zu cap=%zu pending=17 legal-workers=6 variant=%u\n",
        pressured.hello.conn_id, charged, cap, variant);
    if (variant >= 2) {
      auto header = pressured.Header(0, 6, 3); header.type = protocol::MessageType::RELAY_TO_WORKER;
      const size_t rejected = v8host::EncodeRunEnvelope(GuestRelay(0, 3)).size();
      if (charged + rejected != cap + 1 ||
          !pressured.Send(protocol::BuildRelayFrame(header, sbox_msg_binary, nullptr, 0))) return false;
      if (variant == 2) {
        std::vector<uint8_t> bytes; protocol::FrameHeader error_header; protocol::ErrorPayload error;
        if (!pressured.Receive(&bytes, &error_header) || error_header.type != protocol::MessageType::ERROR ||
            error_header.conn_id != pressured.hello.conn_id || error_header.session_id != 6 || error_header.run_id != 3 ||
            error_header.request_id != 0 || error_header.version_major != pressured.hello.selected_major ||
            error_header.version_minor != pressured.hello.selected_minor ||
            !protocol::DecodeErrorPayload(bytes.data() + protocol::kFrameHeaderSize,
                bytes.size() - protocol::kFrameHeaderSize, &error) || error.status_code != protocol::StatusCode::ERROR_QUOTA ||
            !ProcessEof(pressured)) { *detail = "addressed ERROR_QUOTA before real EOF"; return false; }
        std::printf("[quota] conn=%u session=6 run=3 request=0 ERROR_QUOTA before EOF; rejected=%zu\n",
            pressured.hello.conn_id, rejected);
      }
      // The EOF variant does not promise a scheduler-specific writer-drain instant.
    }
    pressured.connection.Close();
    for (size_t index = first; index < count; ++index) {
      if (::WaitForSingleObject(broker.Worker(index), 10000) != WAIT_OBJECT_0) return false;
      std::printf("[reaped] pressure worker=%lu\n", ::GetProcessId(broker.Worker(index)));
    }
    *detail = "aggregate unaffected original PID/fresh admission";
    if (::WaitForSingleObject(survivor, 0) != WAIT_TIMEOUT || ::WaitForSingleObject(broker.process, 0) != WAIT_TIMEOUT ||
        !ProcessEcho(healthy, 1, 1, "survivor-" + std::to_string(variant)) ||
        !ProcessCreate(healthy, 3 + variant * 2, 2 + variant) ||
        !ProcessStart(healthy, 4 + variant * 2, 2 + variant, 1, true) || !broker.Observe(++count)) return false;
  }
  healthy.connection.Close();
  if (!broker.Reaped(count)) return false;
  *detail = "real inbound cap-1/cap/cap+1; addressed quota-before-EOF; six held workers/17 pending; sibling/fresh admission/reap";
  return true;
}

bool RealNoncooperativeFallbackBody(std::string* detail) {
  CapturedBroker broker; ProcessSessionRecord blocked, sibling;
  *detail = "noncooperative real-client marker/admission";
  if (!broker.Launch(detail) || !blocked.Create()) return false;
  const std::string guest = "host.postMessage('entered');for(;;){}";
  V8HostRunInputs input = {}; input.struct_size = sizeof(input); input.tier_override = -1;
  input.payload = guest.data(); input.payload_len = guest.size();
  blocked.runs.emplace_back(); blocked.runs[0].token = "entered";
  if (blocked.client.start(blocked.handle, &input, &blocked.runs[0].handle) != V8HOST_OK ||
      !PumpPublic([&] { return !blocked.runs[0].messages.empty() || blocked.runs[0].terminals || blocked.disconnects; }) ||
      !blocked.valid || blocked.disconnects || blocked.runs[0].terminals ||
      blocked.runs[0].events != std::vector<int32_t>{V8HOST_RUN_EVENT_STARTED} ||
      blocked.runs[0].messages != std::vector<std::vector<uint8_t>>{ProcessSessionRecord::Text("entered")} ||
      blocked.runs[0].kinds != std::vector<int32_t>{sbox_msg_string} || !broker.Observe(1)) return false;
  HANDLE worker = broker.Worker(0);
  if (!worker || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT || !blocked.Start("pending-never-execute") ||
      !PumpPublic([&] { return !blocked.runs[1].events.empty(); }) || !sibling.Create() ||
      !sibling.Start("survivor") || !MapPublicWorker(broker, sibling, 1)) return false;
  HANDLE healthy = broker.Worker(1);
  const ULONGLONG cancelled = ::GetTickCount64();
  if (blocked.client.cancel(blocked.runs[0].handle) != V8HOST_OK ||
      !blocked.Terminal(0, V8HOST_RUN_EVENT_WORKER_EXITED, V8HOST_E_RUN_TERMINAL) ||
      !blocked.Terminal(1, V8HOST_RUN_EVENT_WORKER_EXITED, V8HOST_E_RUN_TERMINAL) ||
      !blocked.runs[1].messages.empty() || blocked.disconnects ||
      ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT) { *detail = "fallback must retire once before kernel death"; return false; }
  const ULONGLONG retired = ::GetTickCount64();
  if (retired - cancelled < 4500 || !sibling.Echo(0, "during-reap", 0x31)) return false;
  std::printf("[fallback] broker=%lu worker=%lu entered-before-cancel=1 retired_ms=%llu WORKER_EXITED active+pending once\n",
      ::GetProcessId(broker.process), ::GetProcessId(worker), retired - cancelled);
  *detail = "noncooperative core timeout/reap (scoped 60-second budget, no harness kill)";
  const ULONGLONG deadline = retired + 60000; ULONGLONG next_echo = retired + 10000;
  while (::WaitForSingleObject(worker, 100) == WAIT_TIMEOUT && ::GetTickCount64() < deadline) {
    DrainPublic();
    if (!blocked.valid || blocked.runs[0].terminals != 1 || blocked.runs[1].terminals != 1 ||
        !blocked.runs[1].messages.empty() || blocked.disconnects || ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT ||
        ::WaitForSingleObject(broker.process, 0) != WAIT_TIMEOUT) return false;
    if (::GetTickCount64() >= next_echo) {
      if (!sibling.Echo(0, "reap-progress", 0x32)) return false;
      next_echo += 10000;
    }
  }
  DWORD code = 0;
  if (::WaitForSingleObject(worker, 0) != WAIT_OBJECT_0 || !::GetExitCodeProcess(worker, &code) || code != 0xDEAD) return false;
  std::printf("[reaped] noncooperative worker=%lu exit=%lu cancel_to_exit_ms=%llu harness_kill=0 budget_ms=60000\n",
      ::GetProcessId(worker), code, ::GetTickCount64() - cancelled);
  for (auto& run : blocked.runs)
    if (blocked.client.post(run.handle, sbox_msg_string, "late", 4) != V8HOST_E_RUN_TERMINAL ||
        blocked.client.cancel(run.handle) != V8HOST_E_RUN_TERMINAL) return false;
  blocked.Close(); const size_t frozen = blocked.CallbackCount();
  V8HostRun* forbidden = nullptr;
  if (blocked.client.start(blocked.handle, &input, &forbidden) == V8HOST_OK || forbidden ||
      !sibling.Echo(0, "after-reap", 0x33) || !sibling.Finish(0) || !sibling.Start("fresh-js") ||
      !sibling.Armed(1) || !sibling.Echo(1, "original-pid", 0x34) || !sibling.Finish(1) ||
      !broker.Observe(2) || ::WaitForSingleObject(healthy, 0) != WAIT_TIMEOUT) return false;
  sibling.Close();
  if (!broker.Reaped(2)) return false;
  DrainPublic();
  { std::lock_guard<std::mutex> lock(broker.mutex);
    if (broker.diagnostics.find("[broker] target timed out; terminating") == std::string::npos) return false;
  }
  *detail = "entered marker; once-only WORKER_EXITED at fallback; core timeout/0xDEAD reap; sibling/fresh JS original PID";
  return blocked.valid && sibling.valid && blocked.CallbackCount() == frozen && !sibling.disconnects;
}
bool RealIdleLifecycleBody(std::string* detail) {
  CapturedBroker broker; WireHarness owner, reuse;
  *detail = "live owner/armed worker prevents shared idle exit";
  if (!OpenCaptured(broker, owner, detail) || !ProcessStart(owner, 2, 1, 1, true) || !broker.Observe(1)) return false;
  HANDLE worker = broker.Worker(0);
  if (::WaitForSingleObject(broker.process, 5500) != WAIT_TIMEOUT || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT ||
      !ProcessEcho(owner, 1, 1, "owner-alive") ||
      !ConnectAndHandshake(BrokerMode::kShared, 900, &reuse.connection, &reuse.hello, detail) ||
      reuse.connection.broker_pid() != ::GetProcessId(broker.process) || reuse.hello.conn_id == owner.hello.conn_id) return false;
  owner.connection.Close();
  *detail = "worker reaped while other authenticated owner preserves broker";
  if (::WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0 ||
      ::WaitForSingleObject(broker.process, 5500) != WAIT_TIMEOUT || !ProcessCreate(reuse, 1, 1)) return false;
  reuse.connection.Close();
  // Broad grace cancellation, not an attempt to hit the exact cutoff instant.
  if (::WaitForSingleObject(broker.process, 1500) != WAIT_TIMEOUT) return false;
  WireHarness renewed;
  if (!ConnectAndHandshake(BrokerMode::kShared, 900, &renewed.connection, &renewed.hello, detail) ||
      renewed.connection.broker_pid() != ::GetProcessId(broker.process) || !ProcessCreate(renewed, 1, 1) ||
      ::WaitForSingleObject(broker.process, 5500) != WAIT_TIMEOUT ||
      !renewed.Send(protocol::BuildCloseSessionFrame(renewed.Header(2))) ||
      !renewed.Expect(protocol::MessageType::ACK, 2, 1)) return false;
  const ULONGLONG closed = ::GetTickCount64(); renewed.connection.Close();
  *detail = "complete-zero shared idle exit and exact-set replacement";
  if (!broker.Reaped(1) || ::GetTickCount64() - closed < 4900) return false;
  CapturedBroker replacement; WireHarness fresh;
  if (!OpenCaptured(replacement, fresh, detail) || ::GetProcessId(replacement.process) == ::GetProcessId(broker.process) ||
      !ProcessStart(fresh, 2, 1, 1, true) || !replacement.Observe(1) || !ProcessEcho(fresh, 1, 1, "replacement-js")) return false;
  fresh.connection.Close();
  if (!replacement.Reaped(1) || !DedicatedOwnerExit(detail)) return false;
  *detail = "shared reuse/live worker/live owner/grace cancellation/complete-zero exit/replacement; dedicated owner-loss drain";
  return true;
}
bool IdleAcceptBoundary(std::string* detail) {
  for (bool completed : {false, true}) {
    const std::wstring name = L"\\\\.\\pipe\\v8host-idle-accept-" + std::to_wstring(::GetCurrentProcessId());
    HANDLE pipe = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr);
    OVERLAPPED pending = {}; pending.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE client = INVALID_HANDLE_VALUE;
    bool active = pipe != INVALID_HANDLE_VALUE && pending.hEvent &&
        !::ConnectNamedPipe(pipe, &pending) && ::GetLastError() == ERROR_IO_PENDING;
    bool ok = active && V8HostBrokerPollConnect(pipe, &pending, 0) == V8HostBrokerAcceptStatus::kPending;
    if (ok && completed) {
      client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
      ok = client != INVALID_HANDLE_VALUE && ::WaitForSingleObject(pending.hEvent, 3000) == WAIT_OBJECT_0 &&
          V8HostBrokerPollConnect(pipe, &pending, 0) == V8HostBrokerAcceptStatus::kConnected;
    }
    if (ok) {
      const bool admitted = V8HostBrokerFinishPendingConnect(pipe, &pending); active = false;
      DWORD transferred = 0;
      const bool succeeded = ::GetOverlappedResult(pipe, &pending, &transferred, FALSE) != FALSE;
      const DWORD error = succeeded ? ERROR_SUCCESS : ::GetLastError();
      ok = admitted == completed && ::WaitForSingleObject(pending.hEvent, 0) == WAIT_OBJECT_0 &&
          (completed ? succeeded : !succeeded && error == ERROR_OPERATION_ABORTED);
      if (ok && admitted) {
        std::vector<uint8_t> sent = protocol::BuildHelloFrame(protocol::FrameHeader{}), received(512);
        ok = PipeIo(client, true, &sent) && PipeIo(pipe, false, &received) && received == sent;
      }
      std::printf("[accept] completed=%d admitted=%d event_signaled=%d error=%lu real-pipe=1\n",
          completed, admitted, ::WaitForSingleObject(pending.hEvent, 0) == WAIT_OBJECT_0, error);
    }
    if (active) { ::CancelIoEx(pipe, &pending); DWORD bytes; ::GetOverlappedResult(pipe, &pending, &bytes, TRUE); }
    if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
    if (pending.hEvent) ::CloseHandle(pending.hEvent);
    if (pipe != INVALID_HANDLE_VALUE) ::CloseHandle(pipe);
    if (!ok) { *detail = completed ? "completed accept must win with exact HELLO" : "cancelled pending accept must drain, not admit"; return false; }
  }
  *detail = "pending polls retained; completed accept wins; cancelled accept drained with ERROR_OPERATION_ABORTED";
  return true;
}

bool IsolatedPublicCase(const char* name, std::string* detail) {
  namespace fs = std::filesystem;
  static std::atomic<unsigned> sequence{0};
  wchar_t temp[MAX_PATH] = {};
  if (!::GetTempPathW(MAX_PATH, temp)) { *detail = "fixture temp path"; return false; }
  const fs::path root = fs::path(temp) / L"v8host-broker-tests" /
      (L"fixture-" + std::to_wstring(::GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence));
  const fs::path dir = root / L"x64";
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) { *detail = "fixture directory: " + ec.message(); return false; }
  struct Cleanup {
    fs::path root;
    ~Cleanup() {
      std::error_code error; fs::remove_all(root, error);
      if (error) std::printf("[cleanup] fixture removal failed: %s\n", error.message().c_str());
    }
  } cleanup{root};
  for (const wchar_t* file : {L"v8host_broker_tests.exe", L"sbox.exe", L"v8host.dll", L"v8jsisb.dll",
      L"msvcp140.dll", L"msvcp140_atomic_wait.dll", L"vcruntime140.dll", L"vcruntime140_1.dll"}) {
    fs::copy_file(fs::path(ExecutableDirectory()) / file, dir / file, fs::copy_options::none, ec);
    if (ec) { *detail = "fixture copy: " + ec.message(); return false; }
  }
  {
    std::ofstream trailer(dir / L"sbox.exe", std::ios::binary | std::ios::app);
    trailer << "\nfixture:" << ::GetCurrentProcessId() << ':' << sequence.load() << ':' << ::GetTickCount64();
    trailer.close();
    if (!trailer) { *detail = "fixture container trailer"; return false; }
  }
  v8host::PayloadIdentity original, isolated;
  v8host::HeldFile original_engine, isolated_engine;
  DWORD error = 0;
  std::vector<uint8_t> sid;
  LUID session;
  std::wstring a, b;
  std::array<uint8_t, 32> key;
  if (!v8host::ResolvePayloadIdentity(ExecutableDirectory(), L"sbox.exe", L"v8host.dll", &original, &error) ||
      !v8host::ResolvePayloadIdentity(dir.wstring(), L"sbox.exe", L"v8host.dll", &isolated, &error) ||
      original.plugin.sha256() != isolated.plugin.sha256() ||
      original.container.sha256() == isolated.container.sha256() ||
      !v8host::OpenImmutableFile(ExecutableDirectory() + L"\\v8jsisb.dll", &original_engine, &error) ||
      !v8host::OpenImmutableFile((dir / L"v8jsisb.dll").wstring(), &isolated_engine, &error) ||
      original_engine.sha256() != isolated_engine.sha256() ||
      !v8host::QueryCurrentSidAndSession(&sid, &session, &error) ||
      !v8host::DeriveEndpoint(sid, original.plugin_set_id, BrokerMode::kShared, nullptr, &a, &key) ||
      !v8host::DeriveEndpoint(sid, isolated.plugin_set_id, BrokerMode::kShared, nullptr, &b, &key) || a == b) {
    *detail = "fixture identity/endpoint not isolated"; return false;
  }
  std::printf("[fixture] distinct exact-set endpoints; immutable DLL hashes identical; case=%s\n", name);
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
  HANDLE read = nullptr, write = nullptr;
  if (!::CreatePipe(&read, &write, &sa, 0)) { *detail = "fixture capture pipe"; return false; }
  ::SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOW startup = {}; startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES; startup.hStdOutput = startup.hStdError = write;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  const std::wstring exe = (dir / L"v8host_broker_tests.exe").wstring();
  std::wstring command = L"\"" + exe + L"\" --public-child=" + std::wstring(name, name + std::strlen(name));
  HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    if (job) ::CloseHandle(job);
    ::CloseHandle(read); ::CloseHandle(write); *detail = "fixture kill-on-close job"; return false;
  }
  PROCESS_INFORMATION pi = {};
  const bool launched = ::CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr,
      dir.c_str(), &startup, &pi) != FALSE;
  ::CloseHandle(write);
  if (!launched) { ::CloseHandle(job); ::CloseHandle(read); *detail = "fixture child launch"; return false; }
  if (!::AssignProcessToJobObject(job, pi.hProcess) || ::ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
    ::TerminateProcess(pi.hProcess, 1); ::WaitForSingleObject(pi.hProcess, 5000);
    ::CloseHandle(pi.hThread); ::CloseHandle(pi.hProcess); ::CloseHandle(read); ::CloseHandle(job);
    *detail = "fixture child job ownership"; return false;
  }
  ::CloseHandle(pi.hThread);
  std::string output;
  bool overflow = false;
  std::thread reader([&] {
    char bytes[4096]; DWORD len;
    while (::ReadFile(read, bytes, sizeof(bytes), &len, nullptr) && len) {
      if (output.size() + len <= 1024 * 1024) output.append(bytes, len);
      else overflow = true;
    }
  });
  bool exited = ::WaitForSingleObject(pi.hProcess, 120000) == WAIT_OBJECT_0;
  if (!exited) { ::TerminateJobObject(job, 1); ::WaitForSingleObject(pi.hProcess, 5000); }
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {};
  const bool empty = ::QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
      &accounting, sizeof(accounting), nullptr) && accounting.ActiveProcesses == 0;
  if (!empty) {
    ::TerminateJobObject(job, 1);
    // Drain only the owned failed fixture job before removing its files.
    const ULONGLONG drain_deadline = ::GetTickCount64() + 5000;
    while (::QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
        &accounting, sizeof(accounting), nullptr) && accounting.ActiveProcesses &&
        ::GetTickCount64() < drain_deadline) ::Sleep(10);
    if (accounting.ActiveProcesses) std::printf("[cleanup] fixture job did not drain\n");
  }
  DWORD code = 1; ::GetExitCodeProcess(pi.hProcess, &code);
  ::CloseHandle(pi.hProcess);
  reader.join(); ::CloseHandle(read); ::CloseHandle(job);
  std::printf("%s", output.c_str());
  const bool passed = exited && empty && !overflow && code == 0 &&
      output.find("[cleanup]") == std::string::npos &&
      output.find(std::string("child/") + name + ": PASS") != std::string::npos;
  if (!passed) *detail = "isolated child exit=" + std::to_string(code) + " exited=" + std::to_string(exited) +
      " job_empty=" + std::to_string(empty) + " overflow=" + std::to_string(overflow);
  return passed;
}
bool RealNoncooperativeFallback(std::string* detail) { return IsolatedPublicCase("real-noncooperative-fallback", detail); }
bool RealIdleLifecycle(std::string* detail) { return IsolatedPublicCase("real-idle-lifecycle", detail); }
bool RealInboundAggregate(std::string* detail) { return IsolatedPublicCase("real-inbound-aggregate", detail); }
bool PublicRealJs(std::string* detail) { return IsolatedPublicCase("real-js", detail); }
bool PublicRealDedicatedJs(std::string* detail) { return IsolatedPublicCase("real-dedicated-js", detail); }
bool PublicRealCancelAndProfile(std::string* detail) { return IsolatedPublicCase("real-cancel-and-profile", detail); }
bool PublicBrokerKill(std::string* detail) { return IsolatedPublicCase("broker-kill-no-replay", detail); }
bool PublicDisconnect(std::string* detail) { return IsolatedPublicCase("disconnect-orderings", detail); }
bool PublicWorkerExit(std::string* detail) { return IsolatedPublicCase("worker-exit-isolation", detail); }
bool SameConnectionWorkerExit(std::string* detail) { return IsolatedPublicCase("same-connection-worker-exit", detail); }
bool PublicNSession(std::string* detail) { return IsolatedPublicCase("n-session-n-pid", detail); }
bool PublicDllIsolation(std::string* detail) {
  *detail = "unrelated owner/child isolation/reap check";
  CapturedBroker unrelated;
  WireHarness owner;
  if (!OpenCaptured(unrelated, owner, detail) ||
      !owner.Send(protocol::BuildStartRunFrame(owner.Header(2, 1, 1), Script(
          "host.onmessage=function(m){host.postMessage(m);};host.postMessage('owner');"))) ||
      !owner.Expect(protocol::MessageType::ACK, 2, 1, 1) ||
      !owner.Expect(protocol::MessageType::STARTUP_READY, 0, 1) ||
      !owner.Expect(protocol::MessageType::SECURITY_READY, 0, 1) ||
      !ExpectString(owner, 1, "owner") || !unrelated.Observe(1)) return false;
  HANDLE worker = unrelated.Worker(0);
  for (const char* name : {"real-js", "real-dedicated-js", "real-cancel-and-profile"}) {
    if (!IsolatedPublicCase(name, detail) || ::WaitForSingleObject(worker, 0) != WAIT_TIMEOUT ||
        ::WaitForSingleObject(unrelated.process, 0) != WAIT_TIMEOUT ||
        !SendString(owner, 1, name) || !ExpectString(owner, 1, name) || !unrelated.Observe(1)) return false;
  }
  owner.connection.Close();
  return unrelated.Reaped(1);
}

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strncmp(argv[i], "--public-child=", 15) != 0) continue;
    std::string name = argv[i] + 15, detail;
    bool ok = name == "real-noncooperative-fallback" ? RealNoncooperativeFallbackBody(&detail) :
        name == "real-idle-lifecycle" ? RealIdleLifecycleBody(&detail) :
        name == "real-inbound-aggregate" ? RealInboundAggregateBody(&detail) :
        name == "real-js" ? PublicRealJsMode(V8HOST_BROKER_SHARED, &detail) :
        name == "real-dedicated-js" ? PublicRealJsMode(V8HOST_BROKER_DEDICATED, &detail) :
        name == "real-cancel-and-profile" ? PublicRealCancelAndProfileBody(&detail) :
        name == "n-session-n-pid" ? PublicNSessionBody(&detail) :
        name == "worker-exit-isolation" ? PublicWorkerExitBody(&detail) :
        name == "same-connection-worker-exit" ? SameConnectionWorkerExitBody(&detail) :
        name == "disconnect-orderings" ? PublicDisconnectBody(&detail) :
        name == "broker-kill-no-replay" && PublicBrokerKillBody(&detail);
    std::printf("child/%s: %s - %s\n", name.c_str(), ok ? "PASS" : "FAIL", detail.c_str());
    return ok ? 0 : 1;
  }
  const std::vector<v8host::test::TestCase> tests = {
      {"cancel", "real-noncooperative-fallback", RealNoncooperativeFallback},
      {"rendezvous", "real-idle-lifecycle", RealIdleLifecycle},
      {"rendezvous", "idle-accept-boundary", IdleAcceptBoundary},
      {"quota", "real-inbound-aggregate", RealInboundAggregate},
      {"crash", "broker-kill-no-replay", PublicBrokerKill},
      {"broker-crash", "broker-kill-no-replay", PublicBrokerKill},
      {"run", "public-js", PublicRealJs},
      {"session", "public-dedicated-js", PublicRealDedicatedJs},
      {"cancel", "public-cancel-and-profile", PublicRealCancelAndProfile},
      {"crash", "disconnect-orderings", PublicDisconnect},
      {"crash", "worker-exit-isolation", PublicWorkerExit},
      {"worker-crash", "worker-exit-isolation", PublicWorkerExit},
      {"no-crosstalk", "n-session-n-pid", PublicNSession},
      {"no-crosstalk", "same-connection-worker-exit", SameConnectionWorkerExit},
      {"worker-crash", "same-connection-worker-exit", SameConnectionWorkerExit},
      {"crash", "same-connection-worker-exit", SameConnectionWorkerExit},
      {"client", "real-dll-isolation", PublicDllIsolation},
      {"client", "real-js", PublicRealJs},
      {"client", "real-dedicated-js", PublicRealDedicatedJs},
      {"client", "real-cancel-and-profile", PublicRealCancelAndProfile},
      {"router", "discard-intake-ordering", DiscardIntakeOrdering},
      {"cancel", "terminal-before-fallback", TerminalBeforeFallback},
      {"router", "bookkeeping-callback-overlap", BookkeepingCallbackOverlap},
      {"router", "ledger-hazard-churn", LedgerHazardChurn},
      {"quota", "run-pressure-containment", RunPressureContainment},
      {"quota", "retry-session-containment", RetrySessionContainment},
      {"quota", "paused-disconnect", PausedDisconnect},
      {"quota", "output-loss-sticky", OutputLossSticky},
      {"router", "final-reply-mailbox", FinalReplyMailbox},
      {"quota", "credit-all-paths", CreditAllPaths},
      {"lifetime", "terminal-contender-orderings", TerminalContenderOrderings},
      {"lifetime", "remove-before-close", TerminalContenderOrderings},
      {"lifetime", "joined-teardown", JoinedTeardown},
      {"lifetime", "complete-zero-drain", CompleteZeroDrain},
      {"lifetime", "idle-held-cleanup", CompleteZeroDrain},
      {"quota", "pause-resume", PauseResume},
      {"router", "worker-mailbox-overflow", WorkerMailboxOverflow},
      {"router", "id-exhaustion", IdExhaustion},
      {"quota", "relay-run-boundary", RelayRunBoundary},
      {"quota", "relay-connection-boundary", RelayConnectionBoundary},
      {"quota", "inbound-error-drain", InboundErrorDrain},
      {"quota", "control-boundary", ControlBoundary},
      {"router", "worker-ring-retry-exhaustion", RetryExhaustion},
      {"router", "worker-ring-full", RetryFifoCredits},
      {"router", "terminal-orderings", TerminalOrderings},
      {"router", "connection-joined", ConnectionJoined},
      {"router", "persistent-control", PersistentControl},
      {"router", "header-direction-reject", HeaderDirectionReject},
      {"router", "unknown-type-ignored", UnknownTypeIgnored},
      {"router", "unknown-must-understand", UnknownMustUnderstand},
      {"router", "control-cache", ControlCache},
      {"router", "id-retirement", IdRetirement},
      {"router", "control-budget", ControlBudget},
      {"router", "start-admission-validation", StartAdmissionValidation},
      {"cancel", "queued-cancels-first", QueuedCancelsFirst},
      {"cancel", "timeout-close-order", TimeoutCloseOrder},
      {"cancel", "timeout-pending-read", TimeoutPendingRead},
      {"session", "reaping-admission-quota", ReapingSessionQuota},
      {"router", "worker-mailbox-pump-bound", MailboxPumpBound},
      {"cancel", "cancels-first", CancelsFirst},
      {"cancel", "completes-first", CompletesFirst},
      {"run", "lifecycle-abi5", LifecycleAbi5},
      {"run", "exit-fact-origin", ExitFactOrigin},
      {"run", "exit-fact-final-drain", ExitFinalDrain},
      {"run", "smoke-lifecycle-two", SmokeLifecycleTwo},
      {"run", "worker-post-kind-guard", WorkerKindGuard},
      {"run", "lifecycle-post-fail-startup", LifecycleFailStartup},
      {"run", "lifecycle-post-fail-security", LifecycleFailSecurity},
      {"run", "post-lockdown-ping-fail", PingPostFail},
      {"lifetime", "early-worker-exit", LifecycleFailSecurity},
      {"lifetime", "exit-cleanup-orderings", ExitCleanupOrderings},
      {"run", "start-spawn", StartSpawn},
      {"run", "real-two-run-reuse", RealTwoRunReuse},
      {"lifetime", "close-live-worker", CloseLiveWorker},
      {"lifetime", "disconnect-live-worker", DisconnectLiveWorker},
      {"run", "start-relay-same-drain", StartRelaySameDrain},
      {"run", "start-bridge-overflow", StartBridgeOverflow},
      {"cancel", "start-cancel-same-drain", StartCancelSameDrain},
      {"run", "coordinator-terminal-holds-next-start", CoordinatorTerminalHoldsNext},
      {"session", "create-close-loop", CreateCloseLoop},
      {"run", "relay-hold-before-ready", RelayHoldBeforeReady},
      {"run", "relay-hold-next-run", RelayHoldNextRun},
      {"run", "readiness-provenance", ReadinessProvenance},
      {"run", "lifecycle-order", LifecycleOrder},
      {"run", "lifecycle-wrong-worker", LifecycleWrongWorker},
      {"run", "first-run-binding", FirstRunBinding},
      {"run", "profile-conflict-invalid", ProfileConflictInvalid},
      {"run", "worker-output-zero-id", WorkerOutputZeroId},
      {"run", "start-admission-quota", StartAdmissionQuota},
      {"run", "envelope-size-boundary", EnvelopeSizeBoundary},
      {"run", "definite-post-failure", DefinitePostFailure},
      {"run", "spawn-failure", SpawnFailure},
      {"run", "mailbox-boundary", MailboxBoundary},
      {"run", "mailbox-readout", MailboxReadout},
      {"run", "mailbox-failure-sticky", MailboxFailureSticky},
      {"run", "relay-mailbox-fairness", RelayMailboxFairness},
      {"run", "inline-read-mailbox", InlineReadMailbox},
      {"run", "held-relay-budget", HeldRelayBudget},
      {"lifetime", "close-publication-orderings", CloseDuringPublication},
      {"session", "quota-32", SessionQuota32},
      {"router", "profile-validation", ProfileValidation},
      {"session", "hello-version-reject", HelloVersionReject},
      {"session", "create-ready", CreateReady},
      {"session", "config-fidelity-0", ConfigFidelity0},
      {"session", "config-fidelity-64", ConfigFidelity64},
      {"rendezvous", "pending-accept-cancellation", PendingAcceptCancellation},
      {"rendezvous", "pending-accept-poll", PendingAcceptPoll},
      {"rendezvous", "shared-fan-in", SharedFanIn},
      {"rendezvous", "exact-payload-separation", ExactPayloadSeparation},
      {"rendezvous", "dedicated-unique", DedicatedUnique},
      {"rendezvous", "mixed-mode", MixedMode},
      {"rendezvous", "idle-exit-relaunch", IdleExitRelaunch},
      {"rendezvous", "grace-cancel", GraceCancel},
      {"rendezvous", "no-generic-client-role", NoGenericClientRole},
      {"peer-auth", "endpoint-squatter", EndpointSquatter},
      {"peer-auth", "immutable-write", ImmutableWrite},
      {"peer-auth", "mutable-preexisting-sharing", MutablePreexisting},
      {"peer-auth", "immutable-mutation", ImmutableMutation},
      {"peer-auth", "canonical-install-root", PathPolicy},
      {"peer-auth", "compile-time-unsigned-policy", TrustPolicy},
      {"peer-auth", "same-user-positive", AuthSameUserPositive},
      {"peer-auth", "cross-user-reject", AuthCrossUserReject},
      {"peer-auth", "wrong-session-reject", AuthWrongSessionReject},
      {"peer-auth", "wrong-payload-image-reject", AuthWrongPayloadImageReject},
      {"peer-auth", "non-co-located-reject", AuthNonColocatedReject},
      {"peer-auth", "sibling-prefix-reject", AuthSiblingPrefixReject},
      {"peer-auth", "dedicated-non-co-located-positive",
       AuthDedicatedNonColocatedPositive},
      {"peer-auth", "launch-instance-mismatch-reject", AuthLaunchMismatchReject},
      {"peer-auth", "pid-reread-mismatch-reject", AuthPidRereadMismatchReject},
      {"peer-auth", "query-failure-reject", AuthQueryFailureReject},
      {"peer-auth", "pid-read-failure-reject", AuthPidReadFailureReject},
      {"peer-auth", "invalid-pipe-reject", AuthInvalidPipeReject},
      {"lifetime", "dedicated-owner-disconnect", DedicatedOwnerExit},
      {"lifetime", "connect-disconnect-races", DisconnectRaces},
      {"lifetime", "broker-api-ownership", BrokerApiOwnership},
      {"lifetime", "broker-api-leaked-cleanup", BrokerApiLeakedCleanup},
      {"lifetime", "host-rejects-bad-plugin-abi", HostRejectsBadPluginAbi},
  };
  return v8host::test::RunTests(argc, argv, tests);
}
