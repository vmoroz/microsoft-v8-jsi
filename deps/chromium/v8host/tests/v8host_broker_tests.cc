#include "v8host_test_support.h"

#include "v8host_broker_rendezvous.h"
#include "v8host_file_identity.h"
#include "v8host_payload_identity.h"
#include "v8host_peer_auth.h"
#include "v8host_router.h"

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
    return Receive(&bytes, &h) && h.type == type && h.conn_id == hello.conn_id && h.request_id == request &&
        h.session_id == session && h.run_id == run;
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
bool StartNotYetEnabled(std::string *detail) {
  router::Connection conn;
  OpenLocal(conn);
  router::Router service(BrokerMode::kDedicated);
  if (!LocalRoute(service, conn, protocol::BuildCreateSessionFrame(ControlHeader(1), LogicalConfig())))
    return false;
  DrainLocal(conn);
  protocol::StartRunPayload start;
  start.tier_override = -1;
  start.guest_payload = {'x'};
  if (!LocalRoute(service, conn, protocol::BuildStartRunFrame(ControlHeader(2, 1, 1), start)))
    return false;
  protocol::FrameHeader header;
  protocol::StatusCode code;
  const auto &session = *conn.sessions.at(1);
  if (!PopFrame(conn, &header, &code) || header.type != protocol::MessageType::ERROR ||
      code != protocol::StatusCode::ERROR_BAD_STATE || session.profile_bound || session.worker ||
      !session.runs.empty() || session.state != router::SessionState::kLogicalReady)
    return false;
  WireHarness h;
  if (!h.Open(detail) || !h.Send(protocol::BuildCreateSessionFrame(h.Header(1), LogicalConfig())) ||
      !h.Expect(protocol::MessageType::ACK, 1, 1) || !h.Expect(protocol::MessageType::SESSION_READY, 0, 1) ||
      !h.Send(protocol::BuildStartRunFrame(h.Header(2, 1, 1), start)) ||
      !h.Expect(protocol::MessageType::ERROR, 2, 1, 1) || !h.Send(protocol::BuildCloseSessionFrame(h.Header(3))) ||
      !h.Expect(protocol::MessageType::ACK, 3, 1))
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
      {"router", "start-not-yet-enabled", StartNotYetEnabled},
      {"session", "quota-32", SessionQuota32},
      {"router", "profile-validation", ProfileValidation},
      {"session", "hello-version-reject", HelloVersionReject},
      {"session", "create-ready", CreateReady},
      {"session", "config-fidelity-0", ConfigFidelity0},
      {"session", "config-fidelity-64", ConfigFidelity64},
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
