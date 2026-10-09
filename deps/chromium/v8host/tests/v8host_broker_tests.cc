#include "v8host_test_support.h"

#include "v8host_broker_rendezvous.h"
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

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
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
    *handle = reinterpret_cast<sbox_broker_worker>(&f);
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Post(sbox_broker_worker handle, sbox_msg_kind kind, const void *data, size_t size) {
    auto &f = *reinterpret_cast<RouterFixture *>(handle);
    if (f.closes)
      ++f.post_after_close;
    v8host::RunEnvelope env;
    if (f.fail_post || kind != sbox_msg_binary || !v8host::DecodeRunEnvelope(static_cast<const uint8_t *>(data), size, &env))
      return sbox_error;
    f.posts.push_back(std::move(env));
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Close(sbox_broker_worker handle) {
    auto &f = *reinterpret_cast<RouterFixture *>(handle);
    ++f.closes;
    if (!f.worker || f.conn.sessions.contains(f.worker->session->session_id) || !f.worker->session->runs.empty())
      ++f.close_before_removal;
    return sbox_ok;
  }
  static sbox_status SBOX_CALL Wait(sbox_broker_worker handle, int32_t *code) {
    auto &f = *reinterpret_cast<RouterFixture *>(handle);
    ++f.waits;
    if (f.wait_entered)
      ::SetEvent(f.wait_entered);
    if (f.wait_release)
      ::WaitForSingleObject(f.wait_release, 5000);
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
        f.closes != 1 || f.waits != 1 || f.posts.size() != posts || !f.conn.out_queue.empty() ||
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
  for (auto [phase, size] : std::vector<std::pair<uint8_t, size_t>>{{2,4},{0,4},{3,4},{1,3},{1,5}}) {
    RouterFixture f;
    f.wait_entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    f.wait_release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f.wait_entered || !f.wait_release || !f.Create() || !f.Start(1))
      return false;
    DrainLocal(f.conn);
    auto *worker = f.worker;
    f.Phase(phase, size);
    if (::WaitForSingleObject(f.wait_entered, 3000) != WAIT_OBJECT_0 || !f.conn.sessions.empty() ||
        !worker->engine_image || f.closes != 1 || !f.posts.empty() || !f.conn.out_queue.empty()) {
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
      const bool rejected = f.conn.sessions.empty() && f.closes == 1;
      f.service->Close(f.conn);
      if (!rejected || !f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || f.closes != 1 || f.waits != 1 ||
          f.close_before_removal || f.post_after_close || !f.conn.out_queue.empty()) {
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
bool DefinitePostFailure(std::string *detail) {
  RouterFixture f;
  if (!f.Create() || !f.Start(1))
    return false;
  f.Phase(1);
  f.fail_post = true;
  f.Phase(2);
  f.service->Close(f.conn);
  if (!f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || f.closes != 1 || f.waits != 1 ||
      f.post_after_close || !f.posts.empty()) {
    *detail = "failed post replayed or leaked worker";
    return false;
  }
  return true;
}
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
          !f.conn.out_queue.empty() || ::WaitForSingleObject(f.conn.stop, 0) == WAIT_OBJECT_0 ||
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
    for (uint8_t i = 0; i < (oversize ? 1 : 16); ++i) emit(i);
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
    const bool closed_in_pump = f.conn.sessions.empty() && f.closes == 1;
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
        f.conn.out_queue.empty() && f.posts.size() == 1;
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
      for (int i = 0; i < (mode == 0 ? 16 : 17); ++i)
        router::Worker::OnMessage(f.worker, sbox_msg_lifecycle, phase, 4);
    f.service->Pump(f.conn);
    if (mode == 0) {
      if (f.conn.sessions.empty() || !f.worker->startup || f.worker->mailbox_head != f.worker->mailbox_tail ||
          f.worker->mailbox_failed || f.conn.out_queue.size() != 1 || f.closes)
        return false;
    } else {
      const bool rejected = f.conn.sessions.empty() && f.closes == 1;
      f.service->Close(f.conn);
      if (!rejected || !f.conn.sessions.empty() || !f.conn.retired_sessions.empty() || !f.conn.out_queue.empty() ||
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
  std::vector<HANDLE> workers;
  bool failed = false;
  ~CapturedBroker() {
    if (process) {
      if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0) {
        ::TerminateProcess(process, 1);
        ::WaitForSingleObject(process, 5000);
      }
      ::CloseHandle(process);
    }
    if (reader.joinable())
      reader.join();
    if (output)
      ::CloseHandle(output);
    for (HANDLE worker : workers)
      ::CloseHandle(worker);
  }
  bool Launch(std::string *detail) {
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
    bool ok = ::CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, TRUE, 0, nullptr,
        ExecutableDirectory().c_str(), &startup, &pi) != FALSE;
    ::CloseHandle(write);
    if (!ok) {
      *detail = "captured broker launch failed";
      return false;
    }
    process = pi.hProcess;
    ::CloseHandle(pi.hThread);
    reader = std::thread([this] {
      std::string line;
      char chunk[1024];
      DWORD size;
      while (::ReadFile(output, chunk, sizeof(chunk), &size, nullptr) && size) {
        for (DWORD i = 0; i < size; ++i) {
          if (chunk[i] == '\n') {
            unsigned long pid = 0;
            if (std::sscanf(line.c_str(), "[broker] target created: pid=%lu", &pid) == 1) {
              HANDLE held = ::OpenProcess(SYNCHRONIZE, FALSE, pid);
              std::lock_guard<std::mutex> lock(mutex);
              if (!held || workers.size() >= 32) {
                failed = true;
                if (held)
                  ::CloseHandle(held);
              } else {
                workers.push_back(held);
                std::printf("[captured] target created: pid=%lu\n", pid);
                std::fflush(stdout);
              }
            }
            line.clear();
          } else if (line.size() < 4096) {
            line += chunk[i];
          } else {
            std::lock_guard<std::mutex> lock(mutex);
            failed = true;
          }
        }
      }
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
  bool Reaped(size_t count) {
    if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0)
      return false;
    reader.join();
    return !failed && workers.size() == count && std::all_of(workers.begin(), workers.end(), [](HANDLE h) {
      return ::WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    });
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
  if (LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(4, UINT32_MAX), LogicalConfig())) ||
      !conn.sessions.empty()) {
    *detail = "exhausted id accepted";
    return false;
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

}  // namespace

int main(int argc, char** argv) {
  const std::vector<v8host::test::TestCase> tests = {
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
