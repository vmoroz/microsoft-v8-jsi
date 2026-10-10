// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_test_support.h"  // windows.h first
#include "v8host_client_transport.h"
#include "v8host_dispatcher.h"
#include "v8host_protocol.h"
#include "v8host_protocol_messages.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <functional>
#include <mutex>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace v8host::protocol;
using v8host::client::ClientTransport;
using v8host::client::ClientTransportDelegate;
using v8host::client::FailNextCallbackCopyForTesting;
using v8host::client::LastSessionDeleteThreadIdForTesting;
using v8host::client::LifecycleThreadIdForTesting;
using v8host::client::SetInitializeAfterDispatcherHookForTesting;
using v8host::client::SetInboundStatusObserverForTesting;
using v8host::client::SetTransportFactoryForTesting;
using v8host::client::TransportDisconnect;
using v8host::client::TransportParams;
using v8host::test::TestCase;

bool Fail(std::string* detail, const char* text) {
  *detail = text;
  return false;
}

std::mutex g_init_mutex;
std::condition_variable g_init_cv;
bool g_dispatcher_captured = false;
bool g_racer_calling = false;
V8HostStatus g_main_init_status = V8HOST_E_INTERNAL;
V8HostStatus g_racer_init_status = V8HOST_E_INTERNAL;
DWORD g_initializing_thread = 0;
bool g_preinitialize_output_was_nulled = false;
std::atomic<int> g_inbound_ok{0};
std::atomic<int> g_inbound_invalid{0};
std::atomic<int> g_inbound_other{0};

void InitializeAfterDispatcherHook() {
  std::unique_lock<std::mutex> lock(g_init_mutex);
  g_dispatcher_captured = true;
  g_init_cv.notify_all();
  g_init_cv.wait(lock, [] { return g_racer_calling; });
}

void ObserveInboundStatus(V8HostStatus status) {
  if (status == V8HOST_OK)
    g_inbound_ok.fetch_add(1, std::memory_order_relaxed);
  else if (status == V8HOST_E_INVALID_STATE)
    g_inbound_invalid.fetch_add(1, std::memory_order_relaxed);
  else
    g_inbound_other.fetch_add(1, std::memory_order_relaxed);
}

bool PumpUntil(const std::function<bool()>& done, DWORD timeout = 5000) {
  const ULONGLONG deadline = ::GetTickCount64() + timeout;
  while (!done()) {
    if (::GetTickCount64() >= deadline)
      return done();
    MSG msg;
    if (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
      ::DispatchMessageW(&msg);
    else
      ::MsgWaitForMultipleObjectsEx(0, nullptr, 10, QS_ALLINPUT,
                                    MWMO_INPUTAVAILABLE);
  }
  return true;
}

void Drain() {
  MSG msg;
  while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
    ::DispatchMessageW(&msg);
}

class FakeTransport final : public ClientTransport {
 public:
  explicit FakeTransport(ClientTransportDelegate* delegate)
      : delegate_(delegate) {}

  V8HostStatus Start() override {
    started = true;
    if (inline_failure) delegate_->OnDisconnect(TransportDisconnect::kConnectFailed);
    delegate_->OnConnected(1, kWireVersionMajor, kWireVersionMinor);
    return start_status;
  }
  V8HostStatus SendFrame(const uint8_t* bytes, size_t len) override {
    std::lock_guard<std::mutex> lock(mutex);
    outbound.emplace_back(bytes, bytes + len);
    return send_status;
  }
  uint32_t conn_id() const override { return 1; }
  void Close() override { closed.store(true); }

  std::vector<uint8_t> Frame(size_t index) {
    std::lock_guard<std::mutex> lock(mutex);
    return outbound.at(index);
  }
  size_t FrameCount() {
    std::lock_guard<std::mutex> lock(mutex);
    return outbound.size();
  }
  void Inbound(std::vector<uint8_t> frame) {
    delegate_->OnInboundFrame(frame.data(), frame.size());
  }
  void Disconnect() {
    delegate_->OnDisconnect(TransportDisconnect::kBrokerLost);
  }

  ClientTransportDelegate* delegate_;
  std::mutex mutex;
  std::vector<std::vector<uint8_t>> outbound;
  std::atomic<bool> closed{false};
  bool started = false, inline_failure = false;
  V8HostStatus start_status = V8HOST_OK;
  V8HostStatus send_status = V8HOST_OK;
};

std::mutex& FakesMutex() {
  static std::mutex* const mutex = new std::mutex();
  return *mutex;
}

std::vector<FakeTransport*>& Fakes() {
  static std::vector<FakeTransport*>* const fakes =
      new std::vector<FakeTransport*>();
  return *fakes;
}

ClientTransport* MakeFake(const TransportParams&, ClientTransportDelegate* d) {
  auto* fake = new (std::nothrow) FakeTransport(d);
  if (fake != nullptr) {
    std::lock_guard<std::mutex> lock(FakesMutex());
    Fakes().push_back(fake);
  }
  return fake;
}

FakeTransport* LatestFake() {
  std::lock_guard<std::mutex> lock(FakesMutex());
  return Fakes().back();
}

V8HostSessionConfig BasicConfig() {
  V8HostSessionConfig c = {};
  c.struct_size = sizeof(c);
  c.broker_mode = V8HOST_BROKER_SHARED;
  c.tier = V8HOST_TIER_UNTRUSTED;
  c.prohibit_dynamic_code = 1;
  return c;
}

V8HostRunInputs BasicRun(const void* data = nullptr, size_t len = 0) {
  V8HostRunInputs i = {};
  i.struct_size = sizeof(i);
  i.tier_override = -1;
  i.payload = data;
  i.payload_len = len;
  return i;
}

bool DecodeFrame(const std::vector<uint8_t>& frame,
                 FrameHeader* header,
                 const uint8_t** payload,
                 size_t* payload_len) {
  return DecodeAndValidateFrame(frame.data(), frame.size(), header, payload,
                                payload_len) == DecodeStatus::kOk;
}

std::vector<uint8_t> EventFrame(MessageType type,
                                uint32_t session,
                                uint32_t run = 0) {
  FrameHeader h;
  h.version_major = kWireVersionMajor;
  h.version_minor = kWireVersionMinor;
  h.type = type;
  h.conn_id = 1;
  h.session_id = session;
  h.run_id = run;
  std::vector<uint8_t> out;
  EncodeHeader(h, out);
  return out;
}

// RESULT frames carry the terminal-disposition codec, so build them through the
// protocol builder rather than EventFrame (which is header-only).
std::vector<uint8_t> ResultFrame(uint32_t session,
                                 uint32_t run,
                                 ResultDisposition disposition =
                                     ResultDisposition::kCompleted) {
  FrameHeader h;
  h.version_major = kWireVersionMajor;
  h.version_minor = kWireVersionMinor;
  h.conn_id = 1;
  h.session_id = session;
  h.run_id = run;
  return BuildResultFrame(h, disposition);
}

std::vector<uint8_t> AckFor(const std::vector<uint8_t>& request) {
  FrameHeader h;
  DecodeAndValidateFrame(request.data(), request.size(), &h);
  return BuildAckFrame(h);
}

std::vector<uint8_t> ErrorFor(const std::vector<uint8_t>& request) {
  FrameHeader h;
  DecodeAndValidateFrame(request.data(), request.size(), &h);
  ErrorPayload error;
  error.status_code = StatusCode::ERROR_BAD_STATE;
  error.message = "bad";
  return BuildErrorFrame(h, error);
}

struct Recorder {
  std::vector<int32_t> states;
  std::vector<V8HostStatus> state_status;
  std::vector<int32_t> events;
  std::vector<V8HostStatus> event_status;
  std::vector<int32_t> kinds;
  std::vector<std::string> messages;
  std::atomic<int> total{0};
  int disconnects = 0;
  DWORD callback_thread = 0;
  DWORD state_thread = 0;
  DWORD run_thread = 0;
  DWORD relay_thread = 0;
  DWORD disconnect_thread = 0;
  V8HostSession* session = nullptr;
  V8HostRun* run = nullptr;
  bool close_in_callback = false;
  V8HostStatus after_close = V8HOST_OK;
  V8HostStatus post_after_close = V8HOST_OK;
  V8HostStatus cancel_after_close = V8HOST_OK;
  V8HostStatus set_after_close = V8HOST_OK;
};

V8HostCallbacks Callbacks(Recorder* r);

void V8HOST_CALL OnState(void* context,
                         V8HostSession* session,
                         int32_t state,
                         V8HostStatus status) {
  auto* r = static_cast<Recorder*>(context);
  r->callback_thread = ::GetCurrentThreadId();
  r->state_thread = r->callback_thread;
  r->states.push_back(state);
  r->state_status.push_back(status);
  r->total.fetch_add(1);
  if (r->close_in_callback) {
    r->close_in_callback = false;
    v8host_client_close_session(session);
    V8HostRun* ignored = reinterpret_cast<V8HostRun*>(1);
    V8HostRunInputs input = BasicRun();
    r->after_close = v8host_client_start_run(session, &input, &ignored);
    V8HostCallbacks callbacks = Callbacks(r);
    r->set_after_close = v8host_client_set_callbacks(session, &callbacks);
    if (r->run != nullptr) {
      r->post_after_close =
          v8host_client_post_message(r->run, 1, nullptr, 0);
      r->cancel_after_close = v8host_client_cancel_run(r->run);
    }
  }
}

void V8HOST_CALL OnRun(void* context,
                       V8HostRun* run,
                       int32_t event,
                       V8HostStatus status) {
  auto* r = static_cast<Recorder*>(context);
  r->callback_thread = ::GetCurrentThreadId();
  r->run_thread = r->callback_thread;
  r->events.push_back(event);
  r->event_status.push_back(status);
  r->total.fetch_add(1);
  r->run = run;
}

void V8HOST_CALL OnRelay(void* context,
                         V8HostRun*,
                         int32_t kind,
                         const void* data,
                         size_t len) {
  auto* r = static_cast<Recorder*>(context);
  r->callback_thread = ::GetCurrentThreadId();
  r->relay_thread = r->callback_thread;
  r->kinds.push_back(kind);
  r->messages.emplace_back(len == 0 ? "" : std::string(
      static_cast<const char*>(data), len));
  r->total.fetch_add(1);
}

void V8HOST_CALL OnDisconnect(void* context) {
  auto* r = static_cast<Recorder*>(context);
  r->callback_thread = ::GetCurrentThreadId();
  r->disconnect_thread = r->callback_thread;
  ++r->disconnects;
  r->total.fetch_add(1);
}

V8HostCallbacks Callbacks(Recorder* r) {
  V8HostCallbacks c = {};
  c.struct_size = sizeof(c);
  c.context = r;
  c.on_session_state = OnState;
  c.on_run_event = OnRun;
  c.on_relay_message = OnRelay;
  c.on_broker_disconnect = OnDisconnect;
  return c;
}

V8HostSession* Create(FakeTransport** fake = nullptr) {
  V8HostSessionConfig c = BasicConfig();
  V8HostSession* session = nullptr;
  if (v8host_client_create_session(&c, &session) != V8HOST_OK)
    return nullptr;
  if (fake)
    *fake = LatestFake();
  return session;
}

bool ConcurrentInitializeLifecycle(std::string* detail) {
  if (!g_preinitialize_output_was_nulled)
    return Fail(detail, "pre-initialize create did not null output");
  if (g_main_init_status != V8HOST_OK || g_racer_init_status != V8HOST_OK)
    return Fail(detail, "racing initialize did not remain idempotent");
  if (LifecycleThreadIdForTesting() != g_initializing_thread ||
      v8host::client::Dispatcher::Instance().callback_thread_id() !=
          g_initializing_thread) {
    return Fail(detail, "dispatcher/lifecycle thread binding differs");
  }
  const int baseline = v8host::client::SessionDispatch::live_count();
  V8HostSession* session = Create();
  if (session == nullptr)
    return Fail(detail, "lifecycle create failed");
  v8host_client_close_session(session);
  if (!PumpUntil([&] {
        return LastSessionDeleteThreadIdForTesting() == g_initializing_thread &&
               v8host::client::SessionDispatch::live_count() == baseline;
      })) {
    return Fail(detail, "deferred destruction did not run on callback thread");
  }
  return true;
}

bool ValidateStructSizes(std::string* detail) {
  V8HostSession* out = reinterpret_cast<V8HostSession*>(1);
  V8HostSessionConfig c = BasicConfig();
  c.struct_size = sizeof(c) - 1;
  if (v8host_client_create_session(&c, &out) != V8HOST_E_STRUCT_SIZE ||
      out != nullptr)
    return Fail(detail, "session struct_size/output nulling");
  c = BasicConfig();
  c.struct_size = sizeof(c) + 16;
  if (v8host_client_create_session(&c, &out) != V8HOST_OK || out == nullptr)
    return Fail(detail, "larger session struct rejected");
  V8HostRunInputs input = BasicRun();
  input.struct_size--;
  V8HostRun* run = reinterpret_cast<V8HostRun*>(1);
  if (v8host_client_start_run(out, &input, &run) != V8HOST_E_STRUCT_SIZE ||
      run != nullptr)
    return Fail(detail, "run struct_size/output nulling");
  input = BasicRun();
  input.struct_size = sizeof(input) + 16;
  if (v8host_client_start_run(out, &input, &run) != V8HOST_OK ||
      run == nullptr)
    return Fail(detail, "larger run struct rejected");
  V8HostCallbacks cb = {};
  cb.struct_size = sizeof(cb) - 1;
  if (v8host_client_set_callbacks(out, &cb) != V8HOST_E_STRUCT_SIZE)
    return Fail(detail, "callback struct_size");
  cb.struct_size = sizeof(cb) + 16;
  const bool ok = v8host_client_set_callbacks(out, &cb) == V8HOST_OK;
  v8host_client_close_session(out);
  Drain();
  return ok || Fail(detail, "larger callback struct rejected");
}

bool ValidatePairsAndPolicy(std::string* detail) {
  V8HostSessionConfig c = BasicConfig();
  V8HostFileRule rule{L"x", 1};
  c.file_rules = &rule;
  if (v8host_client_create_session(&c, nullptr) != V8HOST_E_INVALID_ARG)
    return Fail(detail, "null output");
  V8HostSession* out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "non-null/zero file pair");
  c = BasicConfig();
  c.file_rule_count = 1;
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "null/nonzero file pair");
  const wchar_t* cap = L"cap";
  c = BasicConfig();
  c.capabilities = &cap;
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "non-null/zero capability pair");
  c = BasicConfig();
  c.capability_count = 1;
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "null/nonzero capability pair");
  c = BasicConfig();
  c.app_container_profile_name = L"profile";
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "profile without AC");
  c = BasicConfig();
  c.capabilities = &cap;
  c.capability_count = 1;
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "capability without AC");
  c = BasicConfig();
  c.use_app_container = 1;
  out = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "AC without profile");
  c = BasicConfig();
  c.low_privilege_app_container = 1;
  if (v8host_client_create_session(&c, &out) != V8HOST_E_INVALID_ARG)
    return Fail(detail, "LPAC without AC");
  return true;
}

bool ValidateRunPolicyAndOutputs(std::string* detail) {
  V8HostSession* session = Create();
  if (!session)
    return Fail(detail, "create");
  V8HostRun* out = reinterpret_cast<V8HostRun*>(1);
  V8HostRunInputs i = BasicRun();
  i.tier_override = V8HOST_TIER_TRUSTED;
  if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "tier envelope");
  for (int32_t tier : {-2, 2}) {
    i = BasicRun();
    i.tier_override = tier;
    out = reinterpret_cast<V8HostRun*>(1);
    if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
        out != nullptr)
      return Fail(detail, "invalid tier/output");
  }
  const wchar_t* bad[] = {L"a/b.dll", L"a\\b.dll", L"C:x.dll", L".",
                          L"..",      L"a..b",     L"..x",     L"x.."};
  for (const wchar_t* value : bad) {
    i = BasicRun();
    i.engine_dll_override = value;
    out = reinterpret_cast<V8HostRun*>(1);
    if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
        out != nullptr)
      return Fail(detail, "bad engine path/output");
  }
  char byte = 0;
  i = BasicRun(&byte, 0);
  out = reinterpret_cast<V8HostRun*>(1);
  if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "payload pair");
  i = BasicRun(nullptr, 1);
  out = reinterpret_cast<V8HostRun*>(1);
  if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "reverse payload pair");
  i = BasicRun();
  i.startup_snapshot_path = L"";
  out = reinterpret_cast<V8HostRun*>(1);
  if (v8host_client_start_run(session, &i, &out) != V8HOST_E_INVALID_ARG ||
      out != nullptr)
    return Fail(detail, "empty snapshot/output");
  v8host_client_close_session(session);
  Drain();
  return true;
}

bool ConfigRoundTrip(std::string* detail) {
  FakeTransport* zero_fake = nullptr;
  V8HostSession* zero_session = Create(&zero_fake);
  if (zero_session == nullptr)
    return Fail(detail, "create zero");
  FrameHeader zero_header;
  const uint8_t* zero_body = nullptr;
  size_t zero_len = 0;
  CreateSessionPayload zero;
  const auto zero_frame = zero_fake->Frame(0);
  if (!DecodeFrame(zero_frame, &zero_header, &zero_body, &zero_len) ||
      !DecodeCreateSessionPayload(zero_body, zero_len, &zero) ||
      zero.broker_mode != V8HOST_BROKER_SHARED ||
      zero.tier != V8HOST_TIER_UNTRUSTED || zero.integrity != 0 ||
      zero.delayed_integrity != 0 || zero.initial_token != 0 ||
      zero.lockdown_token != 0 || !zero.prohibit_dynamic_code ||
      zero.use_app_container || zero.low_privilege_app_container ||
      !zero.app_container_profile.empty() || !zero.file_rules.empty() ||
      !zero.capabilities.empty()) {
    return Fail(detail, "zero config field fidelity");
  }
  v8host_client_close_session(zero_session);
  Drain();

  std::vector<std::wstring> patterns(64), caps(64);
  std::vector<V8HostFileRule> rules(64);
  std::vector<const wchar_t*> cap_ptrs(64);
  for (size_t n = 0; n < 64; ++n) {
    patterns[n] = L"rule" + std::to_wstring(n);
    caps[n] = L"cap" + std::to_wstring(n);
    rules[n] = {patterns[n].c_str(), static_cast<int32_t>(n & 1)};
    cap_ptrs[n] = caps[n].c_str();
  }
  V8HostSessionConfig c = BasicConfig();
  c.integrity = 3; c.delayed_integrity = 4; c.initial_token = 5;
  c.lockdown_token = 6; c.file_rules = rules.data(); c.file_rule_count = 64;
  c.use_app_container = 1; c.low_privilege_app_container = 1;
  c.app_container_profile_name = L"profile";
  c.capabilities = cap_ptrs.data(); c.capability_count = 64;
  V8HostSession* session = nullptr;
  if (v8host_client_create_session(&c, &session) != V8HOST_OK)
    return Fail(detail, "create 64");
  patterns[0] = L"mutated";
  FrameHeader h; const uint8_t* body; size_t len;
  const auto frame = LatestFake()->Frame(0);
  CreateSessionPayload p;
  bool ok = DecodeFrame(frame, &h, &body, &len) &&
            DecodeCreateSessionPayload(body, len, &p) &&
            p.broker_mode == V8HOST_BROKER_SHARED &&
            p.tier == V8HOST_TIER_UNTRUSTED && p.integrity == 3 &&
            p.delayed_integrity == 4 && p.initial_token == 5 &&
            p.lockdown_token == 6 && p.prohibit_dynamic_code &&
            p.use_app_container && p.low_privilege_app_container &&
            p.app_container_profile == "profile" &&
            p.file_rules.size() == 64 && p.capabilities.size() == 64 &&
            h.session_id != 0 && h.request_id != 0;
  for (size_t n = 0; ok && n < 64; ++n) {
    ok = p.file_rules[n].pattern == "rule" + std::to_string(n) &&
         p.file_rules[n].readonly == ((n & 1) != 0) &&
         p.capabilities[n] == "cap" + std::to_string(n);
  }
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "config roundtrip/copy");
}

bool BoundaryQuotas(std::string* detail) {
  std::vector<V8HostFileRule> rules(65, V8HostFileRule{L"x", 0});
  V8HostSessionConfig config = BasicConfig();
  config.file_rules = rules.data();
  config.file_rule_count = 65;
  V8HostSession* session = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&config, &session) != V8HOST_E_QUOTA ||
      session != nullptr)
    return Fail(detail, "65 file rules not rejected/null");
  std::vector<const wchar_t*> caps(65, L"cap");
  config = BasicConfig();
  config.use_app_container = 1;
  config.app_container_profile_name = L"profile";
  config.capabilities = caps.data();
  config.capability_count = 65;
  session = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&config, &session) != V8HOST_E_QUOTA ||
      session != nullptr)
    return Fail(detail, "65 capabilities not rejected/null");

  std::wstring accepted(kMaxStringBytes, L'a');
  V8HostFileRule long_rule{accepted.c_str(), 0};
  config = BasicConfig();
  config.file_rules = &long_rule;
  config.file_rule_count = 1;
  if (v8host_client_create_session(&config, &session) != V8HOST_OK)
    return Fail(detail, "32-KiB string boundary rejected");
  v8host_client_close_session(session);
  Drain();
  std::wstring rejected(kMaxStringBytes + 1, L'a');
  long_rule.pattern = rejected.c_str();
  session = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&config, &session) != V8HOST_E_QUOTA ||
      session != nullptr)
    return Fail(detail, "32-KiB+1 string not rejected/null");

  FakeTransport* fake = nullptr;
  session = Create(&fake);
  V8HostRunInputs input = BasicRun();
  V8HostRun* runs[5] = {};
  for (int n = 0; n < 4; ++n) {
    if (v8host_client_start_run(session, &input, &runs[n]) != V8HOST_OK)
      return Fail(detail, "four-run boundary rejected");
  }

  runs[4] = reinterpret_cast<V8HostRun*>(1);
  if (v8host_client_start_run(session, &input, &runs[4]) != V8HOST_E_QUOTA ||
      runs[4] != nullptr)
    return Fail(detail, "fifth in-flight run not rejected/null");
  v8host_client_close_session(session);
  Drain();

  session = Create();
  const size_t max_guest =
      kMaxFramePayload - kStartRunFixedSize - 2 * sizeof(uint32_t);
  std::vector<uint8_t> guest(max_guest, 0xA5);
  input = BasicRun(guest.data(), guest.size());
  V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK)
    return Fail(detail, "exact frame ceiling rejected");
  v8host_client_close_session(session);
  Drain();
  session = Create();
  guest.push_back(0xA5);
  input = BasicRun(guest.data(), guest.size());
  run = reinterpret_cast<V8HostRun*>(1);
  const bool over =
      v8host_client_start_run(session, &input, &run) == V8HOST_E_QUOTA &&
      run == nullptr;
  v8host_client_close_session(session);
  Drain();
  return over || Fail(detail, "frame ceiling+1 not rejected/null");
}

bool ExhaustiveFailingOutputNulling(std::string* detail) {
  auto create_fails_null = [&](const V8HostSessionConfig* config) {
    V8HostSession* out = reinterpret_cast<V8HostSession*>(1);
    return v8host_client_create_session(config, &out) != V8HOST_OK &&
           out == nullptr;
  };
  V8HostSessionConfig config = BasicConfig();
  if (!create_fails_null(nullptr))
    return Fail(detail, "null config output");
  config.struct_size--;
  if (!create_fails_null(&config))
    return Fail(detail, "small config output");
  config = BasicConfig();
  config.broker_mode = 2;
  if (!create_fails_null(&config))
    return Fail(detail, "broker enum output");
  config = BasicConfig();
  config.tier = 2;
  if (!create_fails_null(&config))
    return Fail(detail, "tier enum output");
  config = BasicConfig();
  config.file_rule_count = 65;
  if (!create_fails_null(&config))
    return Fail(detail, "count output");
  config = BasicConfig();
  config.use_app_container = 1;
  if (!create_fails_null(&config))
    return Fail(detail, "AppContainer output");

  V8HostSession* session = Create();
  auto start_fails_null = [&](const V8HostRunInputs* input) {
    V8HostRun* out = reinterpret_cast<V8HostRun*>(1);
    return v8host_client_start_run(session, input, &out) != V8HOST_OK &&
           out == nullptr;
  };
  if (!start_fails_null(nullptr))
    return Fail(detail, "null run input output");
  V8HostRunInputs input = BasicRun();
  input.struct_size--;
  if (!start_fails_null(&input))
    return Fail(detail, "small run input output");
  input = BasicRun();
  input.tier_override = 1;
  if (!start_fails_null(&input))
    return Fail(detail, "tier envelope output");
  input = BasicRun();
  input.engine_dll_override = L"..";
  if (!start_fails_null(&input))
    return Fail(detail, "engine path output");
  input = BasicRun();
  input.startup_snapshot_path = L"";
  if (!start_fails_null(&input))
    return Fail(detail, "snapshot output");
  input = BasicRun(nullptr, 1);
  if (!start_fails_null(&input))
    return Fail(detail, "payload pair output");
  std::vector<uint8_t> huge(kMaxFramePayload, 0);
  input = BasicRun(huge.data(), huge.size());
  if (!start_fails_null(&input))
    return Fail(detail, "frame quota output");
  v8host_client_close_session(session);
  Drain();
  return true;
}

bool RunAndRelayRoundTrip(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  char payload[] = "guest";
  V8HostRunInputs i = BasicRun(payload, 5);
  i.engine_dll_override = L"engine.dll";
  i.startup_snapshot_path = L"snap.bin";
  V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &i, &run) != V8HOST_OK)
    return Fail(detail, "start");
  std::memset(payload, 'x', 5);
  FrameHeader h; const uint8_t* body; size_t len;
  StartRunPayload p;
  auto frame = fake->Frame(1);
  if (!DecodeFrame(frame, &h, &body, &len) ||
      !DecodeStartRunPayload(body, len, &p) ||
      std::string(p.guest_payload.begin(), p.guest_payload.end()) != "guest" ||
      p.engine_filename != "engine.dll" || h.run_id == 0)
    return Fail(detail, "start roundtrip/copy");
  char relay[] = "abc";
  if (v8host_client_post_message(run, -7, relay, 3) != V8HOST_OK)
    return Fail(detail, "relay post");
  std::memset(relay, 'z', 3);
  frame = fake->Frame(2);
  int32_t kind; const uint8_t* relay_body; size_t relay_len;
  if (!DecodeFrame(frame, &h, &body, &len) ||
      !DecodeRelayPayload(body, len, &kind, &relay_body, &relay_len) ||
      h.request_id != 0 || kind != -7 || relay_len != 3 ||
      std::memcmp(relay_body, "abc", 3) != 0)
    return Fail(detail, "relay roundtrip/copy");
  if (v8host_client_cancel_run(run) != V8HOST_OK)
    return Fail(detail, "cancel");
  frame = fake->Frame(3);
  if (!DecodeFrame(frame, &h, &body, &len) ||
      h.type != MessageType::CANCEL_RUN || len != 0)
    return Fail(detail, "cancel serialization");
  if (v8host_client_post_message(run, 9, nullptr, 0) != V8HOST_OK)
    return Fail(detail, "empty relay");
  FrameHeader empty_header;
  frame = fake->Frame(4);
  if (!DecodeFrame(frame, &empty_header, &body, &len) || len != 4 ||
      empty_header.request_id != 0 || h.request_id != 4)
    return Fail(detail, "empty relay/request monotonicity");
  v8host_client_close_session(session);
  frame = fake->Frame(5);
  if (!DecodeFrame(frame, &h, &body, &len) ||
      h.type != MessageType::CLOSE_SESSION || h.request_id != 5)
    return Fail(detail, "close control order");
  Drain();
  return true;
}

bool CallbackRoutingAndReplacement(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder a, b;
  V8HostCallbacks ca = Callbacks(&a), cb = Callbacks(&b);
  v8host_client_set_callbacks(session, &ca);
  FrameHeader create_header;
  const auto create_frame = fake->Frame(0);
  DecodeAndValidateFrame(create_frame.data(), create_frame.size(),
                         &create_header);
  std::thread io([&] {
    fake->Inbound(EventFrame(MessageType::SESSION_READY,
                             create_header.session_id));
  });
  io.join();
  v8host_client_set_callbacks(session, &cb);
  if (!PumpUntil([&] { return a.total.load() == 1; }))
    return Fail(detail, "queued callback snapshot");
  V8HostCallbacks clear = {};
  clear.struct_size = sizeof(clear);
  v8host_client_set_callbacks(session, &clear);
  fake->Inbound(EventFrame(MessageType::STARTUP_READY,
                           create_header.session_id));
  Drain();
  const bool ok = a.states.size() == 1 && b.total.load() == 0 &&
                  a.state_thread == ::GetCurrentThreadId();
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "replace/clear/app thread");
}

bool CallbackAllocationFailure(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder prior, rejected;
  V8HostCallbacks first = Callbacks(&prior);
  V8HostCallbacks second = Callbacks(&rejected);
  if (v8host_client_set_callbacks(session, &first) != V8HOST_OK)
    return Fail(detail, "initial callback install");
  FailNextCallbackCopyForTesting();
  if (v8host_client_set_callbacks(session, &second) != V8HOST_E_NO_MEMORY)
    return Fail(detail, "injected callback allocation failure");
  FrameHeader h;
  const auto create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  const bool delivered =
      PumpUntil([&] { return prior.total.load() == 1; }) &&
      rejected.total.load() == 0;
  v8host_client_close_session(session);
  Drain();
  return delivered || Fail(detail, "prior callback table was not retained");
}

bool InboundRunAndTerminal(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks cb = Callbacks(&r);
  v8host_client_set_callbacks(session, &cb);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  v8host_client_start_run(session, &input, &run);
  FrameHeader start;
  const auto start_frame = fake->Frame(1);
  DecodeAndValidateFrame(start_frame.data(), start_frame.size(), &start);
  const auto ack = AckFor(fake->Frame(1));
  const uint8_t msg[] = {'h', 'i'};
  FrameHeader relay_h = start;
  relay_h.type = MessageType::RELAY_FROM_WORKER;
  relay_h.flags = 0;
  const auto relay_frame = BuildRelayFrame(relay_h, 42, msg, sizeof(msg));
  std::thread io([&] {
    fake->Inbound(ack);
    fake->Inbound(relay_frame);
    fake->Inbound(ResultFrame(start.session_id, start.run_id));
    fake->Inbound(
        EventFrame(MessageType::WORKER_EXIT, start.session_id, start.run_id));
  });
  io.join();
  if (!PumpUntil([&] { return r.total.load() >= 3; }))
    return Fail(detail, "inbound callbacks");
  const bool ok = r.events.size() == 2 &&
      r.events[0] == V8HOST_RUN_EVENT_STARTED &&
      r.events[1] == V8HOST_RUN_EVENT_COMPLETED &&
      r.kinds.size() == 1 && r.kinds[0] == 42 && r.messages[0] == "hi" &&
      r.run_thread == ::GetCurrentThreadId() &&
      r.relay_thread == ::GetCurrentThreadId() &&
      v8host_client_post_message(run, 0, nullptr, 0) ==
          V8HOST_E_RUN_TERMINAL &&
      v8host_client_cancel_run(run) == V8HOST_E_RUN_TERMINAL;
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "routing/one terminal/terminal handle");
}

bool InboundCancelledResult(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks cb = Callbacks(&r);
  v8host_client_set_callbacks(session, &cb);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  v8host_client_start_run(session, &input, &run);
  FrameHeader start;
  const auto start_frame = fake->Frame(1);
  DecodeAndValidateFrame(start_frame.data(), start_frame.size(), &start);
  std::thread io([&] {
    fake->Inbound(AckFor(fake->Frame(1)));
    fake->Inbound(ResultFrame(start.session_id, start.run_id,
                              ResultDisposition::kCancelled));
  });
  io.join();
  if (!PumpUntil([&] { return r.total.load() >= 2; }))
    return Fail(detail, "inbound callbacks");
  const bool ok = r.events.size() == 2 &&
                  r.events[0] == V8HOST_RUN_EVENT_STARTED &&
                  r.events[1] == V8HOST_RUN_EVENT_CANCELLED &&
                  v8host_client_cancel_run(run) == V8HOST_E_RUN_TERMINAL;
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "cancelled result -> CANCELLED terminal");
}

bool LateTrafficAfterTerminal(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks callbacks = Callbacks(&r);
  v8host_client_set_callbacks(session, &callbacks);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  v8host_client_start_run(session, &input, &run);
  const auto start_frame = fake->Frame(1);
  FrameHeader start;
  DecodeAndValidateFrame(start_frame.data(), start_frame.size(), &start);

  fake->Inbound(ResultFrame(start.session_id, start.run_id));
  fake->Inbound(AckFor(start_frame));
  const uint8_t byte = 0x5A;
  FrameHeader relay = start;
  relay.type = MessageType::RELAY_FROM_WORKER;
  relay.flags = 0;
  fake->Inbound(BuildRelayFrame(relay, 17, &byte, 1));
  if (!PumpUntil([&] { return r.total.load() == 1; }))
    return Fail(detail, "terminal callback did not arrive");
  Drain();
  const bool ok = r.events.size() == 1 &&
                  r.events[0] == V8HOST_RUN_EVENT_COMPLETED &&
                  r.kinds.empty() && r.total.load() == 1;
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "late ACK/relay delivered after terminal");
}

bool CorrelationMismatchDisconnects(std::string* detail) {
  for (int variant = 0; variant < 3; ++variant) {
    FakeTransport* fake = nullptr;
    V8HostSession* session = Create(&fake);
    Recorder r;
    V8HostCallbacks callbacks = Callbacks(&r);
    v8host_client_set_callbacks(session, &callbacks);
    V8HostRunInputs input = BasicRun();
    V8HostRun* run = nullptr;
    v8host_client_start_run(session, &input, &run);
    const auto request = fake->Frame(1);
    FrameHeader request_header;
    DecodeAndValidateFrame(request.data(), request.size(), &request_header);
    std::vector<uint8_t> response =
        variant == 2 ? ErrorFor(request) : AckFor(request);
    FrameHeader bad;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    DecodeAndValidateFrame(response.data(), response.size(), &bad, &payload,
                           &payload_len);
    if (variant == 0)
      bad.conn_id++;
    else if (variant == 1)
      bad.session_id++;
    else
      bad.run_id++;
    std::vector<uint8_t> mutated;
    EncodeHeader(bad, mutated);
    mutated.insert(mutated.end(), payload, payload + payload_len);
    fake->Inbound(std::move(mutated));
    if (!PumpUntil([&] { return r.total.load() >= 3; }))
      return Fail(detail, "correlation mismatch did not disconnect");
    if (r.disconnects != 1 || r.states.size() != 1 ||
        r.states[0] != V8HOST_SESSION_STATE_CLOSED ||
        r.state_status[0] != V8HOST_E_PROTOCOL || r.events.size() != 1 ||
        r.events[0] != V8HOST_RUN_EVENT_FAILED ||
        r.event_status[0] != V8HOST_E_PROTOCOL) {
      return Fail(detail, "wrong protocol-error terminalization");
    }

    v8host_client_close_session(session);
    Drain();
  }
  return true;
}

bool UnknownRequestIdDisconnects(std::string* detail) {
  for (bool use_error : {false, true}) {
    FakeTransport* fake = nullptr;
    V8HostSession* session = Create(&fake);
    Recorder r;
    V8HostCallbacks callbacks = Callbacks(&r);
    v8host_client_set_callbacks(session, &callbacks);
    V8HostRunInputs input = BasicRun();
    V8HostRun* run = nullptr;
    v8host_client_start_run(session, &input, &run);
    const auto request = fake->Frame(1);
    std::vector<uint8_t> response =
        use_error ? ErrorFor(request) : AckFor(request);
    FrameHeader bad;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    DecodeAndValidateFrame(response.data(), response.size(), &bad, &payload,
                           &payload_len);
    bad.request_id += 0x10000;
    std::vector<uint8_t> mutated;
    EncodeHeader(bad, mutated);
    mutated.insert(mutated.end(), payload, payload + payload_len);
    fake->Inbound(std::move(mutated));
    if (!PumpUntil([&] { return r.total.load() >= 3; }))
      return Fail(detail, "unknown request id did not disconnect");
    if (r.disconnects != 1 || r.events.size() != 1 ||
        r.event_status[0] != V8HOST_E_PROTOCOL || r.states.size() != 1 ||
        r.state_status[0] != V8HOST_E_PROTOCOL) {
      return Fail(detail, "unknown request id protocol outcome");
    }
    v8host_client_close_session(session);
    Drain();
  }
  return true;
}

bool RelayQuotaError(std::string* detail) {
  for (int path = 0; path < 12; ++path) {
    FakeTransport* fake = nullptr; V8HostSession* session = Create(&fake);
    if (!session) return Fail(detail, "quota session");
    Recorder r; auto cb = Callbacks(&r); v8host_client_set_callbacks(session, &cb);
    auto input = BasicRun(); V8HostRun *first = nullptr, *second = nullptr;
    if (v8host_client_start_run(session, &input, &first) != V8HOST_OK ||
        v8host_client_start_run(session, &input, &second) != V8HOST_OK) return Fail(detail, "quota runs");
    FrameHeader h; auto request = fake->Frame(1); DecodeAndValidateFrame(request.data(), request.size(), &h);
    fake->Inbound(AckFor(fake->Frame(0)));
    h.request_id = 0;
    if (path == 2) fake->Inbound(ResultFrame(h.session_id, h.run_id));
    if (path == 3) v8host_client_close_session(session);
    if (path == 4) ++h.session_id;
    if (path == 5) h.run_id += 10;
    if (path == 8) h.request_id = 10000;
    if (path == 9) ++h.conn_id;
    if (path == 11) h.run_id = 0;
    ErrorPayload error; error.status_code = path == 6 ? StatusCode::ERROR_BAD_STATE : StatusCode::ERROR_QUOTA;
    auto frame = path == 7 ? BuildAckFrame(h) : BuildErrorFrame(h, error);
    if (path == 10) frame.pop_back();
    fake->Inbound(frame);
    if (path < 3) {
      fake->Inbound(frame);
      Drain();
      if (r.events.size() != 1 || r.disconnects ||
          r.events[0] != (path == 2 ? V8HOST_RUN_EVENT_COMPLETED : V8HOST_RUN_EVENT_FAILED) ||
          r.event_status[0] != (path == 2 ? V8HOST_OK : V8HOST_E_QUOTA) ||
          v8host_client_cancel_run(first) != V8HOST_E_RUN_TERMINAL ||
          v8host_client_post_message(second, 0, nullptr, 0) != V8HOST_OK)
        return Fail(detail, "quota addressing/duplicate/winner/other-run containment");
      if (path == 0) fake->Inbound(ResultFrame(h.session_id, h.run_id + 1));
      else fake->Disconnect();
      fake->Inbound(frame); Drain();
      if (r.events.size() != 2 || r.event_status[1] != (path == 0 ? V8HOST_OK : V8HOST_E_BROKER_LOST) ||
          r.events[1] != (path == 0 ? V8HOST_RUN_EVENT_COMPLETED : V8HOST_RUN_EVENT_BROKER_LOST) ||
          r.disconnects != (path == 0 ? 0 : 1)) return Fail(detail, "quota then completion/EOF once");
    } else if (path == 3) {
      Drain();
      if (r.total.load() != 0) return Fail(detail, "callbacks after close and late quota");
    } else {
      Drain();
      if (r.events.size() != 2 || r.event_status != std::vector<V8HostStatus>(2, V8HOST_E_PROTOCOL) ||
          r.disconnects != 1 || r.state_status != std::vector<V8HostStatus>{V8HOST_E_PROTOCOL})
        return Fail(detail, "invalid unsolicited quota must fail protocol");
    }
    if (path != 3) v8host_client_close_session(session);
    Drain();
  }
  return true;
}

bool PendingCapacityAndDuplicateAck(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK)
    return Fail(detail, "capacity run setup");
  fake->Inbound(AckFor(fake->Frame(0)));
  fake->Inbound(AckFor(fake->Frame(1)));
  const size_t controls_begin = fake->FrameCount();
  for (uint32_t n = 0; n < kMaxControlQueueRequests; ++n) {
    if (v8host_client_cancel_run(run) != V8HOST_OK)
      return Fail(detail, "accepted capacity cancel rejected");
  }
  const size_t at_capacity = fake->FrameCount();
  if (at_capacity != controls_begin + kMaxControlQueueRequests)
    return Fail(detail, "accepted controls not all sent");
  if (v8host_client_cancel_run(run) != V8HOST_E_QUOTA ||
      fake->FrameCount() != at_capacity)
    return Fail(detail, "capacity+1 sent or lacked explicit quota");

  const auto first_ack = AckFor(fake->Frame(controls_begin));
  for (size_t n = controls_begin; n < at_capacity; ++n)
    fake->Inbound(AckFor(fake->Frame(n)));
  fake->Inbound(first_ack);
  if (fake->closed.load() ||
      v8host_client_post_message(run, 7, nullptr, 0) != V8HOST_OK)
    return Fail(detail, "duplicate ACK falsely terminalized connection");
  v8host_client_close_session(session);
  Drain();
  return true;
}

bool ReentrantClose(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  r.close_in_callback = true;
  V8HostCallbacks cb = Callbacks(&r);
  v8host_client_set_callbacks(session, &cb);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK)
    return Fail(detail, "reentrant close run setup");
  r.run = run;
  FrameHeader h;
  auto create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  if (!PumpUntil([&] { return r.total.load() == 1; }))
    return Fail(detail, "reentrant callback");
  const bool transport_closed = fake->closed.load();
  Drain();
  return (r.after_close == V8HOST_E_INVALID_STATE &&
          r.set_after_close == V8HOST_E_INVALID_STATE &&
          r.post_after_close == V8HOST_E_RUN_TERMINAL &&
          r.cancel_after_close == V8HOST_E_RUN_TERMINAL &&
          transport_closed) ||
         Fail(detail, "reentrant close state");
}

struct ReentrantOps {
  V8HostSession* session = nullptr;
  V8HostRun* run = nullptr;
  V8HostCallbacks replacement = {};
  V8HostStatus post_status = V8HOST_E_INTERNAL;
  V8HostStatus set_status = V8HOST_E_INTERNAL;
  std::atomic<int> calls{0};
};

void V8HOST_CALL OnReentrantPostSet(void* context,
                                    V8HostSession*,
                                    int32_t,
                                    V8HostStatus) {
  auto* ops = static_cast<ReentrantOps*>(context);
  const char value[] = "r";
  ops->post_status =
      v8host_client_post_message(ops->run, 99, value, sizeof(value) - 1);
  ops->set_status =
      v8host_client_set_callbacks(ops->session, &ops->replacement);
  ops->calls.fetch_add(1);
}

bool ReentrantPostAndSet(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run = nullptr;
  v8host_client_start_run(session, &input, &run);
  Recorder replacement;
  ReentrantOps ops;
  ops.session = session;
  ops.run = run;
  ops.replacement = Callbacks(&replacement);
  V8HostCallbacks callbacks = {};
  callbacks.struct_size = sizeof(callbacks);
  callbacks.context = &ops;
  callbacks.on_session_state = &OnReentrantPostSet;
  v8host_client_set_callbacks(session, &callbacks);
  FrameHeader h;
  const auto create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  if (!PumpUntil([&] { return ops.calls.load() == 1; }))
    return Fail(detail, "reentrant post/set callback");
  fake->Inbound(EventFrame(MessageType::STARTUP_READY, h.session_id));
  if (!PumpUntil([&] { return replacement.total.load() == 1; }))
    return Fail(detail, "replacement callback after reentrant set");
  FrameHeader relay;
  const uint8_t* payload = nullptr;
  size_t payload_len = 0;
  const auto frame = fake->Frame(2);
  const bool ok = ops.post_status == V8HOST_OK &&
                  ops.set_status == V8HOST_OK &&
                  DecodeFrame(frame, &relay, &payload, &payload_len) &&
                  relay.type == MessageType::RELAY_TO_WORKER;
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "reentrant post/set outcome");
}

bool BackpressureAndCloseSuppression(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks cb = Callbacks(&r);
  v8host_client_set_callbacks(session, &cb);
  FrameHeader h; auto create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  for (size_t n = 0; n < v8host::client::kSessionQueueCapacity + 10; ++n)
    fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  if (!PumpUntil([&] { return r.total.load() == 1; }))
    return Fail(detail, "backpressure terminal");
  const bool overflow = r.states.size() == 1 &&
      r.states[0] == V8HOST_SESSION_STATE_CLOSED &&
      r.state_status[0] == V8HOST_E_CALLBACK_BACKPRESSURE;
  v8host_client_close_session(session);
  Drain();

  session = Create(&fake);
  Recorder suppressed;
  cb = Callbacks(&suppressed);
  v8host_client_set_callbacks(session, &cb);
  create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  v8host_client_close_session(session);
  Drain();
  return (overflow && suppressed.total.load() == 0) ||
         Fail(detail, "close suppression");
}

bool CloseWhileFloodingNonblocking(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks callbacks = Callbacks(&r);
  v8host_client_set_callbacks(session, &callbacks);
  FrameHeader h;
  const auto create = fake->Frame(0);
  DecodeAndValidateFrame(create.data(), create.size(), &h);
  std::atomic<bool> started{false};
  std::atomic<bool> stop{false};
  std::thread flood([&] {
    started.store(true, std::memory_order_release);
    while (!stop.load(std::memory_order_acquire))
      fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
  });
  while (!started.load(std::memory_order_acquire))
    ::SwitchToThread();
  const ULONGLONG begin = ::GetTickCount64();
  v8host_client_close_session(session);
  const ULONGLONG elapsed = ::GetTickCount64() - begin;
  stop.store(true, std::memory_order_release);
  flood.join();
  Drain();
  return (elapsed < 500 && r.total.load() == 0) ||
         Fail(detail, "close blocked or delivered queued flood callbacks");
}

bool DisconnectNoReplay(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  auto cb = Callbacks(&r);
  v8host_client_set_callbacks(session, &cb);
  V8HostRunInputs input = BasicRun();
  V8HostRun* run1 = nullptr; V8HostRun* run2 = nullptr;
  v8host_client_start_run(session, &input, &run1);
  v8host_client_start_run(session, &input, &run2);
  const size_t before = fake->FrameCount();
  std::thread io([&] { fake->Disconnect(); });
  io.join();
  if (!PumpUntil([&] { return r.total.load() >= 4; }))
    return Fail(detail, "disconnect callbacks");
  const bool ok = fake->FrameCount() == before && r.disconnects == 1 &&
      r.events.size() == 2 && r.states.size() == 1 &&
      r.states[0] == V8HOST_SESSION_STATE_CLOSED &&
      r.state_status[0] == V8HOST_E_BROKER_LOST &&
      r.events[0] == V8HOST_RUN_EVENT_BROKER_LOST &&
      r.events[1] == V8HOST_RUN_EVENT_BROKER_LOST &&
      r.event_status[0] == V8HOST_E_BROKER_LOST &&
      r.event_status[1] == V8HOST_E_BROKER_LOST &&
      r.run_thread == ::GetCurrentThreadId() &&
      r.state_thread == ::GetCurrentThreadId() &&
      r.disconnect_thread == ::GetCurrentThreadId() &&
      v8host_client_cancel_run(run1) == V8HOST_E_RUN_TERMINAL;
  v8host_client_close_session(session);
  const size_t after_close = fake->FrameCount();
  Drain();
  return (ok && after_close == before && fake->closed.load()) ||
         Fail(detail, "disconnect terminalization/replay");
}

bool MalformedFrameDisconnects(std::string* detail) {
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  Recorder r;
  V8HostCallbacks callbacks = Callbacks(&r);
  v8host_client_set_callbacks(session, &callbacks);
  fake->Inbound({0x01, 0x02, 0x03});
  if (!PumpUntil([&] { return r.total.load() >= 2; }))
    return Fail(detail, "malformed frame did not disconnect");
  const bool ok = r.disconnects == 1 && r.states.size() == 1 &&
                  r.states[0] == V8HOST_SESSION_STATE_CLOSED &&
                  r.state_status[0] == V8HOST_E_PROTOCOL;
  v8host_client_close_session(session);
  Drain();
  return ok || Fail(detail, "malformed frame protocol outcome");
}

bool InboundVsCloseRace(std::string* detail) {
  const int baseline = v8host::client::SessionDispatch::live_count();
  g_inbound_ok.store(0);
  g_inbound_invalid.store(0);
  g_inbound_other.store(0);
  SetInboundStatusObserverForTesting(&ObserveInboundStatus);
  for (int cycle = 0; cycle < 1000; ++cycle) {
    FakeTransport* fake = nullptr;
    V8HostSession* session = Create(&fake);
    if (session == nullptr)
      return Fail(detail, "race create");
    FrameHeader h; auto create = fake->Frame(0);
    DecodeAndValidateFrame(create.data(), create.size(), &h);
    std::atomic<bool> started{false};
    std::thread io([&] {
      started.store(true, std::memory_order_release);
      for (int n = 0; n < 16; ++n)
        fake->Inbound(EventFrame(MessageType::SESSION_READY, h.session_id));
    });
    while (!started.load(std::memory_order_acquire))
      ::SwitchToThread();
    v8host_client_close_session(session);
    io.join();
    Drain();
    if (v8host::client::SessionDispatch::live_count() != baseline)
      return Fail(detail, "race lifetime leak");
  }
  SetInboundStatusObserverForTesting(nullptr);
  return (g_inbound_ok.load() + g_inbound_invalid.load() == 16000 &&
          g_inbound_other.load() == 0) ||
         Fail(detail, "race producer outcome outside OK/INVALID_STATE");
}



bool g_inline_start_failure = false;
ClientTransport* MakeStartFailure(const TransportParams& p, ClientTransportDelegate* d) {
  auto* fake = static_cast<FakeTransport*>(MakeFake(p, d));
  fake->start_status = V8HOST_E_CONNECT;
  fake->inline_failure = g_inline_start_failure;
  return fake;
}
bool StartupRegistrationFailure(std::string* detail) {
  for (bool inline_failure : {false, true}) {
    g_inline_start_failure = inline_failure;
  SetTransportFactoryForTesting(MakeStartFailure);
  FakeTransport* fake = nullptr;
  V8HostSession* session = Create(&fake);
  SetTransportFactoryForTesting(MakeFake);
  if (!session) return Fail(detail, "create admission");
  Recorder r; auto callbacks = Callbacks(&r);
  v8host_client_set_callbacks(session, &callbacks);
  auto input = BasicRun(); V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK) return Fail(detail, "prestart run");
  if (!PumpUntil([&] { return r.total.load() >= 3; }) || r.states.size() != 1 || r.events.size() != 1 ||
      r.disconnects != 1 || r.state_status[0] != V8HOST_E_CONNECT ||
      r.events[0] != V8HOST_RUN_EVENT_FAILED || r.event_status[0] != V8HOST_E_CONNECT || !fake->closed)
    return Fail(detail, "startup outcome after registration");
  v8host_client_close_session(session); Drain();
  }
  return true;
}
bool ClientIdExhaustion(std::string* detail) {
  for (bool request : {false, true}) {
    FakeTransport* fake = nullptr; V8HostSession* session = Create(&fake);
    Recorder r; auto callbacks = Callbacks(&r); v8host_client_set_callbacks(session, &callbacks);
    v8host::client::SetIdsForTesting(session, request ? UINT32_MAX : 2, request ? 1 : UINT32_MAX);
    auto input = BasicRun(); V8HostRun* run = reinterpret_cast<V8HostRun*>(1);
    size_t count = fake->FrameCount();
    if (v8host_client_start_run(session, &input, &run) != V8HOST_E_QUOTA || run ||
        !PumpUntil([&] { return r.disconnects == 1; }) || r.states.size() != 1 ||
        r.state_status[0] != V8HOST_E_PROTOCOL || fake->FrameCount() != count)
      return Fail(detail, "id exhaustion must close without wrap/write");
    v8host_client_close_session(session); Drain();
  }
  return true;
}
bool AdmissionRollback(std::string* detail) {
  FakeTransport* fake = nullptr; V8HostSession* session = Create(&fake);
  Recorder r; auto callbacks = Callbacks(&r); v8host_client_set_callbacks(session, &callbacks);
  auto input = BasicRun();
  fake->send_status = V8HOST_E_QUOTA;
  for (unsigned i = 0; i < 300; ++i) {
    V8HostRun* run = reinterpret_cast<V8HostRun*>(1);
    if (v8host_client_start_run(session, &input, &run) != V8HOST_E_QUOTA || run)
      return Fail(detail, "enqueue rejection pending/run rollback");
  }
  fake->send_status = V8HOST_OK;
  V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK || !run)
    return Fail(detail, "admission after quota rejection");
  fake->send_status = V8HOST_E_QUOTA;
  if (v8host_client_post_message(run, 0, nullptr, 0) != V8HOST_E_QUOTA ||
      v8host_client_cancel_run(run) != V8HOST_E_QUOTA)
    return Fail(detail, "post/cancel admission status");
  Drain();
  if (r.disconnects || !r.events.empty()) return Fail(detail, "quota must not masquerade as connect loss");
  fake->send_status = V8HOST_OK; v8host_client_close_session(session); Drain();
  return true;
}

struct TransportProbe {
  HANDLE connected = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE disconnected = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE destroyed = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE inbound = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::atomic<int> connects{0}, losses{0}, frames{0};
  ULONGLONG connected_at = 0, disconnected_at = 0;
  TransportDisconnect reason = TransportDisconnect::kConnectFailed;
  uint32_t conn = 0;
  uint16_t major = 0, minor = 0;
  ~TransportProbe() {
    for (HANDLE h : {connected, disconnected, destroyed, inbound}) ::CloseHandle(h);
  }
};
struct ProbeDelegate : ClientTransportDelegate {
  explicit ProbeDelegate(TransportProbe* p) : probe(p) {}
  ~ProbeDelegate() override { ::SetEvent(probe->destroyed); }
  void OnConnected(uint32_t id, uint16_t major, uint16_t minor) override {
    probe->conn = id; probe->major = major; probe->minor = minor;
    probe->connected_at = ::GetTickCount64(); ++probe->connects;
    ::SetEvent(probe->connected);
  }
  void OnInboundFrame(const uint8_t*, size_t) override {
    ++probe->frames;
    if (close_on_frame) close_on_frame->Close();
    ::SetEvent(probe->inbound);
  }
  void OnDisconnect(TransportDisconnect reason) override {
    probe->reason = reason; probe->disconnected_at = ::GetTickCount64();
    ++probe->losses; ::SetEvent(probe->disconnected);
  }
  ClientTransport* close_on_frame = nullptr;
  TransportProbe* probe;
};
bool Signaled(HANDLE h) { return ::WaitForSingleObject(h, 5000) == WAIT_OBJECT_0; }


enum class LaunchHold { kObserve, kSlow, kExhausted, kClose };
bool g_launch_abort = false;

struct LaunchFixture {
  explicit LaunchFixture(int mode, LaunchHold hold) : mode(mode), hold(hold) {}
  TransportProbe probe;
  const int mode;
  const LaunchHold hold;
  HANDLE in_launch = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE release = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE returned = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::shared_ptr<ProbeDelegate> delegate = std::make_shared<ProbeDelegate>(&probe);
  std::unique_ptr<ClientTransport> transport;
  std::atomic<HANDLE> candidate{nullptr};
  std::atomic<DWORD> hook_error{ERROR_SUCCESS};
  std::atomic<int> before_count{0}, created_count{0}, returned_count{0};
  std::atomic<ULONGLONG> d0{0}, before_enter{0}, before_exit{0};
  std::atomic<ULONGLONG> launch_enter{0}, launch_exit{0}, shifted{0}, observed_at{0};

  void HoldUntil(ULONGLONG until) {
    ULONGLONG now = ::GetTickCount64();
    while (now < until &&
           ::WaitForSingleObject(release, static_cast<DWORD>(until - now)) == WAIT_TIMEOUT)
      now = ::GetTickCount64();
  }
  static void Hook(void* context, v8host::LaunchHookPoint point, HANDLE process,
                   ULONGLONG deadline) {
    auto& f = *static_cast<LaunchFixture*>(context);
    const ULONGLONG now = ::GetTickCount64();
    if (point == v8host::LaunchHookPoint::kBeforeCreate) {
      ++f.before_count;
      f.d0 = deadline; f.before_enter = now;
      if (f.hold == LaunchHold::kExhausted) f.HoldUntil(now + 5000);
      f.before_exit = ::GetTickCount64();
    } else if (point == v8host::LaunchHookPoint::kCreated) {
      if (++f.created_count == 1) {
        HANDLE duplicate = nullptr;
        const DWORD access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION |
            (f.mode == V8HOST_BROKER_DEDICATED ? PROCESS_TERMINATE : 0);
        if (!::DuplicateHandle(::GetCurrentProcess(), process, ::GetCurrentProcess(),
                               &duplicate, access, FALSE, 0))
          f.hook_error = ::GetLastError();
        f.candidate = duplicate;
      }
      f.launch_enter = now;
      ::SetEvent(f.in_launch);
      if (f.hold == LaunchHold::kSlow)
        f.HoldUntil((std::min)(deadline + 500, now + 15000));
      else if (f.hold == LaunchHold::kExhausted)
        f.HoldUntil(now + 10000);
      else if (f.hold == LaunchHold::kClose)
        f.HoldUntil(now + 15000);
      f.launch_exit = ::GetTickCount64();
    } else {
      ++f.returned_count;
      f.shifted = deadline; f.observed_at = now;
      ::SetEvent(f.returned);
    }
  }
  bool Init(std::string* detail) {
    if (!in_launch || !release || !returned || !probe.connected ||
        !probe.disconnected || !probe.destroyed || !probe.inbound)
      return Fail(detail, "launch fixture event creation");
    const std::wstring directory = v8host::test::ExecutableDirectory();
    if (mode == V8HOST_BROKER_SHARED) {
      v8host::PayloadIdentity payload;
      std::vector<uint8_t> sid;
      LUID session = {};
      std::wstring endpoint;
      std::array<uint8_t, 32> key = {};
      DWORD error = ERROR_SUCCESS;
      if (!v8host::ResolvePayloadIdentity(directory, L"sbox.exe", L"v8host.dll", &payload, &error) ||
          !v8host::QueryCurrentSidAndSession(&sid, &session, &error) ||
          !v8host::DeriveEndpoint(sid, payload.plugin_set_id, v8host::BrokerMode::kShared,
                                 nullptr, &endpoint, &key))
        return Fail(detail, "shared endpoint identity resolution");
      if (::WaitNamedPipeW(endpoint.c_str(), 0) || ::GetLastError() != ERROR_FILE_NOT_FOUND)
        return Fail(detail, "shared endpoint present");
    }
    TransportParams params;
    params.payload_directory = directory; params.broker_mode = mode;
    params.test_context = this; params.test_launch = Hook;
    transport.reset(v8host::client::CreateRealPipeClientTransport(params, delegate.get()));
    return transport ? true : Fail(detail, "real launch transport creation");
  }
  bool Start(std::string* detail) {
    if (transport->Start(delegate) != V8HOST_OK)
      return Fail(detail, "real launch transport Start");
    if (::WaitForSingleObject(in_launch, 30000) != WAIT_OBJECT_0)
      return Fail(detail, "launch hook did not start within 30 s");
    return candidate.load() && hook_error == ERROR_SUCCESS
        ? true : Fail(detail, "launch candidate handle duplication");
  }
  bool Hooks(std::string* detail) {
    if (before_count != 1 || created_count != 1 || returned_count != 1)
      return Fail(detail, "launch hook counts must each be one");
    const ULONGLONG lower = d0 + (launch_exit - launch_enter);
    const ULONGLONG upper = d0 + (observed_at - before_exit);
    if (shifted < lower || shifted > upper)
      return Fail(detail, "launch deadline shift outside measured bracket");
    return true;
  }
  bool Cancelled() {
    DWORD code = STILL_ACTIVE;
    return ::WaitForSingleObject(candidate.load(), 0) == WAIT_OBJECT_0 &&
        ::GetExitCodeProcess(candidate.load(), &code) && code == ERROR_CANCELLED;
  }
  void ReapFailedDedicated() {
    HANDLE process = candidate.load();
    if (mode == V8HOST_BROKER_DEDICATED && process &&
        ::WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
      ::TerminateProcess(process, 0xFA11);
      if (::WaitForSingleObject(process, 5000) != WAIT_OBJECT_0)
        g_launch_abort = true;
    }
  }
  bool Finish(bool passed, std::string* detail) {
    ::SetEvent(release);
    if (transport) transport->Close();
    transport.reset();
    delegate.reset();
    if (::WaitForSingleObject(probe.destroyed, 15000) != WAIT_OBJECT_0) {
      ReapFailedDedicated();
      g_launch_abort = true;
      *detail += " teardown timed out; fixture retained";
      return false;
    }
    HANDLE process = candidate.load();
    if (process) {
      if (passed && (probe.losses != (hold == LaunchHold::kExhausted ? 1 : 0) ||
                     probe.connects != (hold == LaunchHold::kClose ||
                                       hold == LaunchHold::kExhausted ? 0 : 1)))
        passed = Fail(detail, "late or duplicate launch callbacks");
      if (mode == V8HOST_BROKER_DEDICATED) {
        if (passed && (hold == LaunchHold::kClose || hold == LaunchHold::kExhausted) && !Cancelled())
          passed = Fail(detail, "dedicated candidate not cancelled at destruction");
        if (::WaitForSingleObject(process, passed ? 8000 : 0) != WAIT_OBJECT_0) {
          passed = Fail(detail, "dedicated candidate did not exit");
          ReapFailedDedicated();
        }
      } else {
        if (passed && ::WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
          passed = Fail(detail, "shared candidate exited before idle grace");
        if (::WaitForSingleObject(process, 10000) != WAIT_OBJECT_0) {
          passed = Fail(detail, "shared candidate idle exit timed out");
          g_launch_abort = true;
        } else {
          DWORD code = STILL_ACTIVE;
          if (!::GetExitCodeProcess(process, &code) || code != 0)
            passed = Fail(detail, "shared candidate exit was not idle success");
        }
      }
      DWORD code = STILL_ACTIVE;
      ::GetExitCodeProcess(process, &code);
      *detail += " pid=" + std::to_string(::GetProcessId(process)) +
          " exit=" + std::to_string(code) + " shift=" + std::to_string(shifted - d0) +
          " bracket=[" + std::to_string(d0 + launch_exit - launch_enter) + "," +
          std::to_string(d0 + observed_at - before_exit) + "] D=" + std::to_string(shifted) +
          " hooks=" + std::to_string(before_count) + "/" + std::to_string(created_count) +
          "/" + std::to_string(returned_count);
    }
    delete this;
    return passed;
  }
  ~LaunchFixture() {
    if (candidate.load()) ::CloseHandle(candidate.load());
    for (HANDLE h : {in_launch, release, returned}) if (h) ::CloseHandle(h);
  }
};

bool LaunchCase(std::string* detail, int mode, LaunchHold hold) {
  auto* f = new LaunchFixture(mode, hold);
  const bool passed = [&] {
    if (!f->Init(detail) || !f->Start(detail)) return false;
    if (hold == LaunchHold::kClose) {
      const ULONGLONG close_start = ::GetTickCount64();
      f->transport->Close();
      const ULONGLONG close_end = ::GetTickCount64();
      ::SetEvent(f->release);
      if (close_end - close_start > 1000)
        return Fail(detail, "Close blocked during launch");
      const DWORD timeout = mode == V8HOST_BROKER_SHARED ? 2000 : 5000;
      // Drop the test lease before observing background destruction.
      f->transport.reset(); f->delegate.reset();
      if (::WaitForSingleObject(f->probe.destroyed, timeout) != WAIT_OBJECT_0)
        return Fail(detail, "post-release destruction exceeded bound");
      if (!f->Hooks(detail)) return false;
      return f->probe.connects == 0 && f->probe.losses == 0
          ? true : Fail(detail, "callbacks after Close during launch");
    }
    if (::WaitForSingleObject(f->returned, 30000) != WAIT_OBJECT_0)
      return Fail(detail, "rendezvous did not return");
    if (!f->Hooks(detail)) return false;
    if (hold == LaunchHold::kExhausted) {
      if (::WaitForSingleObject(f->probe.disconnected, 5000) != WAIT_OBJECT_0 ||
          f->probe.connects != 0 || f->probe.losses != 1 ||
          f->probe.reason != TransportDisconnect::kConnectFailed ||
          f->probe.disconnected_at - f->launch_exit > 3000 || !f->Cancelled())
        return Fail(detail, "exhausted non-launch budget or joined cancellation");
    } else {
      if (::WaitForSingleObject(f->probe.connected, 5000) != WAIT_OBJECT_0 ||
          f->probe.connects != 1 || !f->probe.conn || f->probe.losses != 0 ||
          (hold == LaunchHold::kSlow && f->probe.connected_at - f->launch_exit > 5000))
        return Fail(detail, "real launch did not connect within startup budget");
    }
    return true;
  }();
  return f->Finish(passed, detail);
}

struct PumpFixture {
  TransportProbe probe;
  HANDLE server = INVALID_HANDLE_VALUE, client = INVALID_HANDLE_VALUE;
  HANDLE gate = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE entered = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE read_pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE write_pending = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::shared_ptr<ProbeDelegate> delegate = std::make_shared<ProbeDelegate>(&probe);
  std::unique_ptr<ClientTransport> transport;
  std::atomic<int> attempts{0};
  std::vector<v8host::RendezvousStatus> results;
  bool started = false;
  ULONGLONG observed_deadline = 0;
  bool consistent_deadline = true;
  static v8host::RendezvousStatus Connect(void* context, v8host::BrokerConnection* conn,
                                         v8host::HelloResult* hello, HANDLE stop, ULONGLONG deadline) {
    auto& f = *static_cast<PumpFixture*>(context);
    int attempt = f.attempts.fetch_add(1);
    if (!f.observed_deadline) f.observed_deadline = deadline;
    f.consistent_deadline &= f.observed_deadline == deadline;
    ::SetEvent(f.entered);
    HANDLE events[] = {stop, f.gate};
    ULONGLONG now = ::GetTickCount64();
    DWORD remaining = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
    if (::WaitForMultipleObjects(2, events, FALSE, remaining) != WAIT_OBJECT_0 + 1)
      return v8host::RendezvousStatus::kStartTimeout;
    auto status = attempt < static_cast<int>(f.results.size()) ? f.results[attempt] : v8host::RendezvousStatus::kOk;
    if (status != v8host::RendezvousStatus::kOk) return status;
    conn->AdoptForTesting(f.client); f.client = INVALID_HANDLE_VALUE;
    hello->conn_id = 37; hello->selected_major = 1; hello->selected_minor = 7;
    return status;
  }
  static void Pending(void* context, bool write) {
    auto& f = *static_cast<PumpFixture*>(context);
    ::SetEvent(write ? f.write_pending : f.read_pending);
  }
  bool Init(int mode = V8HOST_BROKER_SHARED) {
    static std::atomic<unsigned> serial{0};
    std::wstring name = LR"(\\.\pipe\v8host-client-test-)" + std::to_wstring(::GetCurrentProcessId()) +
        L"-" + std::to_wstring(++serial);
    server = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) return false;
    OVERLAPPED accept = {}; accept.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL accepted = ::ConnectNamedPipe(server, &accept);
    DWORD error = ::GetLastError();
    client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                          OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    DWORD ignored = 0;
    bool ok = client != INVALID_HANDLE_VALUE &&
        (accepted || error == ERROR_PIPE_CONNECTED || (error == ERROR_IO_PENDING &&
          Signaled(accept.hEvent) && ::GetOverlappedResult(server, &accept, &ignored, FALSE)));
    if (!ok) { ::CancelIoEx(server, &accept); ::GetOverlappedResult(server, &accept, &ignored, TRUE); }
    ::CloseHandle(accept.hEvent);
    if (!ok) return false;
    DWORD readmode = PIPE_READMODE_MESSAGE;
    if (!::SetNamedPipeHandleState(client, &readmode, nullptr, nullptr)) return false;
    TransportParams p; p.broker_mode = mode; p.test_context = this;
    p.test_connect = Connect; p.test_pending = Pending;
    transport.reset(v8host::client::CreateRealPipeClientTransport(p, delegate.get()));
    return transport != nullptr;
  }
  bool Start() {
    started = transport->Start(delegate) == V8HOST_OK;
    return started && Signaled(entered);
  }
  bool Finish() {
    transport->Close(); transport->Close();
    delegate.reset();
    return !started || Signaled(probe.destroyed);
  }
  ~PumpFixture() {
    if (transport) Finish();
    if (server != INVALID_HANDLE_VALUE) ::CloseHandle(server);
    if (client != INVALID_HANDLE_VALUE) ::CloseHandle(client);
    for (HANDLE h : {gate, entered, read_pending, write_pending}) ::CloseHandle(h);
  }
  bool Io(bool write, std::vector<uint8_t>* bytes) {
    OVERLAPPED op = {}; op.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    DWORD size = 0;
    BOOL ok = write ? ::WriteFile(server, bytes->data(), static_cast<DWORD>(bytes->size()), nullptr, &op)
                    : ::ReadFile(server, bytes->data(), static_cast<DWORD>(bytes->size()), nullptr, &op);
    if (!ok && ::GetLastError() == ERROR_IO_PENDING)
      ok = Signaled(op.hEvent) && ::GetOverlappedResult(server, &op, &size, FALSE);
    else if (ok) ok = ::GetOverlappedResult(server, &op, &size, FALSE);
    if (!ok) { ::CancelIoEx(server, &op); ::GetOverlappedResult(server, &op, &size, TRUE); }
    ::CloseHandle(op.hEvent);
    if (ok && !write) bytes->resize(size);
    return ok != FALSE;
  }
  V8HostStatus Send(const std::vector<uint8_t>& bytes) {
    return transport->SendFrame(bytes.data(), bytes.size());
  }
};

PumpFixture* g_client_pipe = nullptr;
ClientTransport* MakeClientPipe(const TransportParams& params, ClientTransportDelegate* delegate) {
  auto p = params; p.test_context = g_client_pipe;
  p.test_connect = PumpFixture::Connect; p.test_pending = PumpFixture::Pending;
  return v8host::client::CreateRealPipeClientTransport(p, delegate);
}
bool RealClientFailurePaths(std::string* detail) {
  for (int path = 0; path < 4; ++path) {
    PumpFixture f; if (!f.Init()) return Fail(detail, "client pipe pair");
    g_client_pipe = &f; SetTransportFactoryForTesting(&MakeClientPipe);
    struct ResetFactory { ~ResetFactory() { SetTransportFactoryForTesting(&MakeFake); g_client_pipe = nullptr; } } reset;
    if (path == 0) f.results = {v8host::RendezvousStatus::kProtocolFailed};
    V8HostSession* session = Create();
    if (!session) return Fail(detail, "real transport client create");
    struct CloseSession { V8HostSession* session; ~CloseSession() { if (session) v8host_client_close_session(session); } } cleanup{session};
    Recorder r; auto callbacks = Callbacks(&r); v8host_client_set_callbacks(session, &callbacks);
    auto input = BasicRun(); V8HostRun* run = nullptr;
    if (v8host_client_start_run(session, &input, &run) != V8HOST_OK) return Fail(detail, "real transport client start");
    ::SetEvent(f.gate);
    if (!PumpUntil([&] { return ::WaitForSingleObject(f.entered, 0) == WAIT_OBJECT_0; }))
      return Fail(detail, "real client scheduled startup");
    if (path != 0) {
      std::vector<uint8_t> frame(kMaxFrameSize);
      FrameHeader h;
      for (int n = 0; n < 2; ++n) {
        frame.resize(kMaxFrameSize);
        if (!f.Io(false, &frame) || !DecodeFrame(frame, &h, nullptr, nullptr) ||
            h.conn_id != 37 || h.version_minor != 7 || h.request_id != static_cast<uint32_t>(n + 2))
          return Fail(detail, "real client negotiated CREATE/START FIFO");
      }
      if (!Signaled(f.read_pending)) return Fail(detail, "real client pending read");
      if (path == 1) { ::CloseHandle(f.server); f.server = INVALID_HANDLE_VALUE; }
      else {
        h.request_id = 0; h.version_minor = path == 3 ? 6 : 7;
        frame = BuildResultFrame(h, ResultDisposition::kCompleted);
        if (path == 2) frame.pop_back();
        if (!f.Io(true, &frame)) return Fail(detail, "real client invalid inbound write");
      }
    }
    if (!PumpUntil([&] { return r.disconnects == 1; })) return Fail(detail, "real client failure callbacks");
    Drain();
    const V8HostStatus expected = path == 0 ? V8HOST_E_CONNECT : path == 1 ? V8HOST_E_BROKER_LOST : V8HOST_E_PROTOCOL;
    if (r.events.size() != 1 || r.event_status != std::vector<V8HostStatus>{expected} ||
        r.events[0] != (path == 1 ? V8HOST_RUN_EVENT_BROKER_LOST : V8HOST_RUN_EVENT_FAILED) ||
        r.state_status != std::vector<V8HostStatus>{expected} || r.states != std::vector<int32_t>{V8HOST_SESSION_STATE_CLOSED} ||
        r.run_thread != ::GetCurrentThreadId() || r.disconnect_thread != ::GetCurrentThreadId() ||
        f.attempts != 1 || v8host_client_cancel_run(run) != V8HOST_E_RUN_TERMINAL)
      return Fail(detail, "real client failure once/app-thread/no replay");
    v8host_client_close_session(session); cleanup.session = nullptr; Drain();
  }
  return true;
}

std::vector<uint8_t> SizedTransportFrame(size_t len, bool relay, uint32_t run = 1) {
  FrameHeader h; h.version_major = 1;
  h.type = relay ? MessageType::RELAY_TO_WORKER : MessageType::START_RUN;
  h.session_id = 1; h.run_id = run; h.request_id = relay ? 0 : run + 1;
  h.payload_length = static_cast<uint32_t>(len - kFrameHeaderSize);
  std::vector<uint8_t> bytes; EncodeHeader(h, bytes); bytes.resize(len, 0x61);
  return bytes;
}
bool TransportFifo(std::string* detail) {
  PumpFixture f;
  if (!f.Init()) return Fail(detail, "pipe pair");
  FrameHeader header; header.version_major = 1; header.session_id = 1; header.request_id = 2;
  CreateSessionPayload config; config.broker_mode = 1; config.prohibit_dynamic_code = true;
  auto create = BuildCreateSessionFrame(header, config);
  header.request_id = 3; header.run_id = 1;
  StartRunPayload inputs; inputs.guest_payload = {'x'};
  auto start = BuildStartRunFrame(header, inputs);
  header.request_id = 0; header.type = MessageType::RELAY_TO_WORKER;
  const uint8_t message[] = {'a', 'b'};
  auto relay = BuildRelayFrame(header, -7, message, sizeof(message));
  const std::vector<std::vector<uint8_t>> expected = {create, start, relay};
  const MessageType types[] = {MessageType::CREATE_SESSION, MessageType::START_RUN, MessageType::RELAY_TO_WORKER};
  if (f.Send(create) || f.Send(start) || f.Send(relay) || !f.Start()) return Fail(detail, "preconnect admission");
  std::fill(start.begin(), start.end(), 0xFF);
  DWORD available = 1;
  if (!::PeekNamedPipe(f.server, nullptr, 0, nullptr, &available, nullptr) || available)
    return Fail(detail, "application write before ACK");
  ::SetEvent(f.gate);
  if (!Signaled(f.probe.connected)) return Fail(detail, "connected publication");
  for (unsigned i = 0; i < 3; ++i) {
    std::vector<uint8_t> bytes(kMaxFrameSize);
    FrameHeader h;
    if (!f.Io(false, &bytes) || DecodeAndValidateFrame(bytes.data(), bytes.size(), &h) != DecodeStatus::kOk ||
        h.conn_id != 37 || h.version_major != 1 || h.version_minor != 7 ||
        h.type != types[i] || h.request_id != (i == 2 ? 0 : i + 2) || bytes.size() != expected[i].size() ||
        !std::equal(bytes.begin() + kFrameHeaderSize, bytes.end(), expected[i].begin() + kFrameHeaderSize))
      return Fail(detail, "FIFO/stamping/deep copy");
  }
  if (!f.Finish() || f.transport->QueuedBytesForTesting() || f.probe.losses ||
      f.Send(create) != V8HOST_E_CONNECT || f.transport->Start(f.delegate) != V8HOST_E_CONNECT)
    return Fail(detail, "closed transport reuse/cleanup");
  return true;
}

bool TransportReadWriteStop(std::string* detail) {
  PumpFixture f;
  if (!f.Init() || !f.Start()) return Fail(detail, "start");
  ::SetEvent(f.gate);
  if (!Signaled(f.read_pending)) return Fail(detail, "genuine pending read");
  auto bytes = SizedTransportFrame(kMaxFrameSize, true);
  if (f.Send(bytes) || !Signaled(f.write_pending) || f.transport->QueuedBytesForTesting() != bytes.size())
    return Fail(detail, "pending write/inflight credit");
  // Both pending operations must be drained before the delegate lease drops.
  if (!f.Finish() || f.probe.losses || f.transport->QueuedBytesForTesting())
    return Fail(detail, "cancel/drain/lease");
  return true;
}


bool TransportWriteLoss(std::string* detail) {
  PumpFixture f;
  if (!f.Init() || !f.Start()) return Fail(detail, "pair/start");
  ::SetEvent(f.gate);
  if (!Signaled(f.read_pending)) return Fail(detail, "pending read");
  auto bytes = SizedTransportFrame(kMaxFrameSize, true);
  if (f.Send(bytes) || !Signaled(f.write_pending)) return Fail(detail, "pending write");
  ::CloseHandle(f.server); f.server = INVALID_HANDLE_VALUE;
  if (!Signaled(f.probe.disconnected) || f.probe.losses != 1 ||
      f.probe.reason != TransportDisconnect::kBrokerLost || f.attempts != 1 ||
      f.Send(bytes) != V8HOST_E_CONNECT || !f.Finish() || f.transport->QueuedBytesForTesting())
    return Fail(detail, "ambiguous write loss must drain, terminalize once, never replay");
  return true;
}

bool FillTransport(PumpFixture& f, size_t total, bool relay, uint32_t run) {
  while (total) {
    size_t len = (std::min)(total, size_t{kMaxFrameSize});
    if (total > len && total - len < 36) len -= 36;
    if (f.Send(SizedTransportFrame(len, relay, run)) != V8HOST_OK) return false;
    total -= len;
  }
  return true;
}
bool TransportQueueBoundaries(std::string* detail) {
  for (size_t offset : {size_t{0}, size_t{1}}) {
    PumpFixture f;
    if (!f.Init() || !FillTransport(f, kMaxControlQueueBytes - offset, false, 1) ||
        f.Send(SizedTransportFrame(32, false)) != V8HOST_E_QUOTA ||
        f.transport->QueuedBytesForTesting() != kMaxControlQueueBytes - offset)
      return Fail(detail, "control byte boundary");
  }
  {
    PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
    for (unsigned i = 0; i < kMaxControlQueueRequests; ++i)
      if (f.Send(SizedTransportFrame(32, false)) != V8HOST_OK) return Fail(detail, "control count cap");
    if (f.Send(SizedTransportFrame(32, false)) != V8HOST_E_QUOTA) return Fail(detail, "control count +1");
  }
  for (size_t offset : {size_t{0}, size_t{1}}) {
    PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
    if (!FillTransport(f, kMaxQueuedRelayBytesPerRun - offset, true, 1) ||
        f.Send(SizedTransportFrame(36, true, 1)) != V8HOST_E_QUOTA ||
        f.transport->QueuedBytesForTesting() != kMaxQueuedRelayBytesPerRun - offset)
      return Fail(detail, "run byte boundary");
  }
  PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
  for (unsigned run = 1; run <= 16; ++run)
    if (!FillTransport(f, kMaxQueuedRelayBytesPerRun, true, run)) return Fail(detail, "connection cap");
  if (f.transport->QueuedBytesForTesting() != kMaxQueuedRelayBytesPerConnection ||
      f.Send(SizedTransportFrame(36, true, 17)) != V8HOST_E_QUOTA || !f.Start())
    return Fail(detail, "connection +1");
  if (!f.Finish() || f.transport->QueuedBytesForTesting()) return Fail(detail, "stop queue credit");
  return true;
}

bool TransportMalformed(std::string* detail) {
  for (int variant = 0; variant < 3; ++variant) {
    PumpFixture f; if (!f.Init() || !f.Start()) return Fail(detail, "pair/start");
    ::SetEvent(f.gate);
    if (!Signaled(f.read_pending)) return Fail(detail, "pending read");
    std::vector<uint8_t> bytes = variant == 0 ? std::vector<uint8_t>{1, 2, 3}
        : SizedTransportFrame(variant == 1 ? 33 : kMaxFrameSize, false);
    if (variant == 1) bytes.pop_back();
    if (variant == 2) bytes.push_back(0);
    if (!f.Io(true, &bytes) || !Signaled(f.probe.disconnected) || f.probe.losses != 1 ||
        f.probe.reason != TransportDisconnect::kProtocolError || !f.Finish() || f.attempts != 1)
      return Fail(detail, "malformed/partial/oversized disconnect");
  }
  return true;
}

bool TransportRetry(std::string* detail) {
  using Status = v8host::RendezvousStatus;
  for (auto status : {Status::kIoFailed, Status::kProtocolFailed, Status::kPeerAuthenticationFailed, Status::kStartTimeout}) {
    for (int mode : {V8HOST_BROKER_SHARED, V8HOST_BROKER_DEDICATED}) {
      PumpFixture f; f.results = {status};
      if (!f.Init(mode) || !f.Start()) return Fail(detail, "script start");
      ::SetEvent(f.gate);
      bool retry = status == Status::kIoFailed && mode == V8HOST_BROKER_SHARED;
      if (!Signaled(retry ? f.probe.connected : f.probe.disconnected) ||
          f.attempts != (retry ? 2 : 1)) return Fail(detail, "preack retry policy");
      if (retry) {
        ::CloseHandle(f.server); f.server = INVALID_HANDLE_VALUE;
        if (!Signaled(f.probe.disconnected) || f.probe.reason != TransportDisconnect::kBrokerLost || f.attempts != 2)
          return Fail(detail, "postack no reconnect");
      }
      if (!f.Finish() || f.probe.losses != 1) return Fail(detail, "sole disconnect");
    }
  }
  PumpFixture expired; expired.results.assign(1000, Status::kIoFailed);
  if (!expired.Init() || !expired.Start()) return Fail(detail, "deadline start");
  ::SetEvent(expired.gate);
  if (::WaitForSingleObject(expired.probe.disconnected, 7000) != WAIT_OBJECT_0 ||
      expired.attempts < 2 || !expired.consistent_deadline || !expired.Finish() || expired.probe.losses != 1)
    return Fail(detail, "one overall preack deadline");
  PumpFixture stopped; if (!stopped.Init() || !stopped.Start() || !stopped.Finish() || stopped.probe.losses)
    return Fail(detail, "cancelled connect");
  return true;
}


HANDLE g_first_admitted = nullptr, g_second_attempted = nullptr;
std::atomic<int> g_submission_before{0}, g_submission_after{0};
bool g_hold_before_submission = false;
std::atomic<bool> g_order_barrier_ok{true};
void BeforeSubmission() {
  const int count = ++g_submission_before;
  if (g_hold_before_submission && count == 1) {
    ::SetEvent(g_first_admitted);
    if (::WaitForSingleObject(g_second_attempted, 5000) != WAIT_OBJECT_0) g_order_barrier_ok = false;
  } else if (!g_hold_before_submission && count == 2) {
    ::SetEvent(g_second_attempted);
  }
}
void AfterSubmission() {
  if (++g_submission_after == 1 && !g_hold_before_submission) {
    ::SetEvent(g_first_admitted);
    if (::WaitForSingleObject(g_second_attempted, 5000) != WAIT_OBJECT_0) g_order_barrier_ok = false;
  }
}
bool ControlIdSendOrder(std::string* detail) {
  for (bool before : {false, true}) {
  g_hold_before_submission = before;
  FakeTransport* fake = nullptr; V8HostSession* session = Create(&fake);
  Recorder r; auto callbacks = Callbacks(&r); v8host_client_set_callbacks(session, &callbacks);
  auto input = BasicRun(); V8HostRun* run = nullptr;
  if (v8host_client_start_run(session, &input, &run) != V8HOST_OK) return Fail(detail, "start");
  g_first_admitted = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_second_attempted = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_submission_before = g_submission_after = 0;
  g_order_barrier_ok = g_first_admitted && g_second_attempted;
  v8host::client::SetSubmissionHooksForTesting(BeforeSubmission, AfterSubmission);
  V8HostStatus first = V8HOST_E_INTERNAL, second = V8HOST_E_INTERNAL;
  std::thread a([&] { first = v8host::client::SubmitCancelForTesting(session, 1); });
  bool entered = Signaled(g_first_admitted);
  std::thread b([&] {
    second = v8host::client::SubmitCancelForTesting(session, 1);
    if (before) ::SetEvent(g_second_attempted);
  });
  a.join(); b.join();
  v8host::client::SetSubmissionHooksForTesting(nullptr, nullptr);
  ::CloseHandle(g_first_admitted); ::CloseHandle(g_second_attempted);
  bool ok = entered && g_order_barrier_ok && first == V8HOST_OK && second == V8HOST_OK && g_submission_before == 2 && g_submission_after == 2;
  for (unsigned i = 2; i < 4; ++i) {
    FrameHeader h; auto frame = fake->Frame(i);
    ok &= DecodeAndValidateFrame(frame.data(), frame.size(), &h) == DecodeStatus::kOk &&
        h.request_id == i + 2 && h.type == MessageType::CANCEL_RUN;
    fake->Inbound(AckFor(frame));
  }
  Drain(); ok &= r.disconnects == 0;
  v8host_client_close_session(session); Drain();
  if (!ok) return Fail(detail, "barrier-controlled allocation/reservation/enqueue order");
  }
  return true;
}
bool TransportCallbackClose(std::string* detail) {
  PumpFixture f; if (!f.Init() || !f.Start()) return Fail(detail, "pair/start");
  f.delegate->close_on_frame = f.transport.get();
  ::SetEvent(f.gate);
  if (!Signaled(f.read_pending)) return Fail(detail, "read pending");
  auto bytes = SizedTransportFrame(32, false);
  if (!f.Io(true, &bytes) || !Signaled(f.probe.inbound) || !f.Finish() || f.probe.frames != 1 || f.probe.losses ||
      f.Send(bytes) != V8HOST_E_CONNECT || f.transport->QueuedBytesForTesting())
    return Fail(detail, "callback close/lease/no replay");
  return true;
}
bool HandshakeRejects(std::string* detail) {
  for (int variant = 0; variant < 5; ++variant) {
    PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
    v8host::BrokerConnection conn; conn.AdoptForTesting(f.client); f.client = INVALID_HANDLE_VALUE;
    v8host::HelloResult hello;
    v8host::RendezvousStatus status = v8host::RendezvousStatus::kOk;
    std::thread handshake([&] { status = conn.Handshake(1, &hello); });
    std::vector<uint8_t> request(kMaxFrameSize);
    bool ok = f.Io(false, &request);
    FrameHeader request_header;
    ok &= DecodeAndValidateFrame(request.data(), request.size(), &request_header) == DecodeStatus::kOk &&
        request_header.type == MessageType::HELLO && request_header.request_id == 1 && request_header.conn_id == 0;
    FrameHeader h; h.version_major = 1; h.conn_id = 37; h.request_id = variant == 1 ? 2 : 1;
    HelloAckPayload ack; ack.broker_version_major = 1;
    auto bytes = BuildHelloAckFrame(h, ack);
    if (variant == 0) bytes[0] = 0;
    if (variant == 2) { h.version_minor = 1; bytes = BuildHelloAckFrame(h, ack); }
    if (variant == 3) bytes = BuildErrorFrame(h, ErrorPayload{});
    if (variant == 4) bytes.resize(513, 0);
    ok &= f.Io(true, &bytes); handshake.join();
    auto expected = variant == 3 ? v8host::RendezvousStatus::kPeerAuthenticationFailed
                                : v8host::RendezvousStatus::kProtocolFailed;
    if (!ok || status != expected || hello.conn_id != 0) return Fail(detail, "invalid/rejected ACK must not be retryable IO");
  }
  return true;
}
bool TransportExactCrossing(std::string* detail) {
  for (bool relay : {false, true}) {
    PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
    const size_t cap = relay ? kMaxQueuedRelayBytesPerRun : kMaxControlQueueBytes;
    if (!FillTransport(f, cap - 35, relay, 1) || f.Send(SizedTransportFrame(36, relay)) != V8HOST_E_QUOTA ||
        f.transport->QueuedBytesForTesting() != cap - 35) return Fail(detail, "exact cap+1 rejection");
  }
  PumpFixture f; if (!f.Init()) return Fail(detail, "pair");
  for (unsigned run = 1; run < 16; ++run)
    if (!FillTransport(f, kMaxQueuedRelayBytesPerRun, true, run)) return Fail(detail, "connection fill");
  if (!FillTransport(f, kMaxQueuedRelayBytesPerRun - 35, true, 16) ||
      f.Send(SizedTransportFrame(36, true, 17)) != V8HOST_E_QUOTA ||
      f.transport->QueuedBytesForTesting() != kMaxQueuedRelayBytesPerConnection - 35)
    return Fail(detail, "connection exact cap+1 rejection");
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  SetTransportFactoryForTesting(&MakeFake);
  V8HostSessionConfig preinit_config = BasicConfig();
  V8HostSession* preinit_session = reinterpret_cast<V8HostSession*>(1);
  g_preinitialize_output_was_nulled =
      v8host_client_create_session(&preinit_config, &preinit_session) ==
          V8HOST_E_NOT_INITIALIZED &&
      preinit_session == nullptr;
  g_initializing_thread = ::GetCurrentThreadId();
  SetInitializeAfterDispatcherHookForTesting(&InitializeAfterDispatcherHook);
  std::thread racer([] {
    {
      std::unique_lock<std::mutex> lock(g_init_mutex);
      g_init_cv.wait(lock, [] { return g_dispatcher_captured; });
      g_racer_calling = true;
      g_init_cv.notify_all();
    }
    g_racer_init_status = v8host_client_initialize();
  });
  g_main_init_status = v8host_client_initialize();
  SetInitializeAfterDispatcherHookForTesting(nullptr);
  racer.join();
  std::vector<TestCase> tests = {
      {"transport", "control-id-send-order", ControlIdSendOrder},
      {"transport", "close-lifetime-no-replay", TransportCallbackClose},
      {"transport", "handshake-rejects", HandshakeRejects},
      {"transport", "real-client-failure-paths", RealClientFailurePaths},
      {"transport", "exact-quota-crossing", TransportExactCrossing},
      {"transport", "startup-registration-failure", StartupRegistrationFailure},
      {"transport", "id-exhaustion", ClientIdExhaustion},
      {"transport", "admission-rollback", AdmissionRollback},
      {"transport", "preconnect-fifo-version", TransportFifo},
      {"transport", "read-write-stop", TransportReadWriteStop},
      {"transport", "write-loss-no-replay", TransportWriteLoss},
      {"transport", "queue-boundaries", TransportQueueBoundaries},
      {"transport", "malformed-message", TransportMalformed},
      {"transport", "preack-retry-policy", TransportRetry},
      {"rendezvous", "real-dedicated-connects", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_DEDICATED, LaunchHold::kObserve); }},
      {"rendezvous", "slow-launch-dedicated-connects", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_DEDICATED, LaunchHold::kSlow); }},
      {"rendezvous", "slow-launch-deadline-shift", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_DEDICATED, LaunchHold::kExhausted); }},
      {"rendezvous", "slow-launch-close-no-orphan", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_DEDICATED, LaunchHold::kClose); }},
      {"rendezvous", "real-shared-connects", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_SHARED, LaunchHold::kObserve); }},
      {"rendezvous", "slow-launch-close-shared-survives", [](std::string* d) {
        return LaunchCase(d, V8HOST_BROKER_SHARED, LaunchHold::kClose); }},
      {"init", "concurrent-thread-binding-destruction",
       ConcurrentInitializeLifecycle},
      {"validate", "struct-sizes", ValidateStructSizes},
      {"validate", "count-pointer-appcontainer", ValidatePairsAndPolicy},
      {"validate", "tier-path-output-nulling", ValidateRunPolicyAndOutputs},
      {"config", "roundtrip-zero-and-64", ConfigRoundTrip},
      {"boundary", "counts-runs-strings-frame", BoundaryQuotas},
      {"output", "all-failing-paths-null", ExhaustiveFailingOutputNulling},
      {"copy", "run-and-relay-roundtrip", RunAndRelayRoundTrip},
      {"callbacks", "replace-clear-app-thread", CallbackRoutingAndReplacement},
      {"callbacks", "alloc-failure-prior-intact", CallbackAllocationFailure},
      {"delivery", "inbound-run-terminal", InboundRunAndTerminal},
      {"delivery", "inbound-cancelled-result", InboundCancelledResult},
      {"delivery", "terminal-then-late-ack-relay", LateTrafficAfterTerminal},
      {"protocol", "wrong-conn-session-run-correlation",
       CorrelationMismatchDisconnects},
      {"protocol", "wrong-request-id-ack-error", UnknownRequestIdDisconnects},
      {"protocol", "relay-quota-error", RelayQuotaError},
      {"protocol", "pending-capacity-and-duplicate-ack",
       PendingCapacityAndDuplicateAck},
      {"protocol", "malformed-frame-disconnect", MalformedFrameDisconnects},
      {"reentrancy", "post-and-set", ReentrantPostAndSet},
      {"reentrancy", "close", ReentrantClose},
      {"backpressure", "overflow-and-close", BackpressureAndCloseSuppression},
      {"close", "flooding-nonblocking", CloseWhileFloodingNonblocking},
      {"disconnect", "no-replay", DisconnectNoReplay},
      {"race", "inbound-vs-close", InboundVsCloseRace},
  };
  for (auto& test : tests) {
    auto run = std::move(test.run);
    test.run = [run = std::move(run), suite = test.suite, name = test.name](std::string* detail) {
      if (g_launch_abort) {
        printf("FAIL - skipping %s/%s and remaining cases after launch teardown failure\n",
               suite, name);
        fflush(stdout);
        ::ExitProcess(1);
      }
      return run(detail);
    };
  }
  return v8host::test::RunTests(argc, argv, tests);
}
