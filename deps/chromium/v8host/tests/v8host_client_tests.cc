// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_test_support.h"  // windows.h first
#include "v8host_client_transport.h"
#include "v8host_dispatcher.h"
#include "v8host_protocol.h"
#include "v8host_protocol_messages.h"

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <mutex>
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
  bool started = false;
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
  const wchar_t* bad[] = {L"a/b.dll", L"a\\b.dll", L"C:x.dll", L".", L".."};
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

  std::wstring accepted(kMaxStringBytes - 1, L'a');
  V8HostFileRule long_rule{accepted.c_str(), 0};
  config = BasicConfig();
  config.file_rules = &long_rule;
  config.file_rule_count = 1;
  if (v8host_client_create_session(&config, &session) != V8HOST_OK)
    return Fail(detail, "32767-byte string boundary rejected");
  v8host_client_close_session(session);
  Drain();
  std::wstring rejected(kMaxStringBytes, L'a');
  long_rule.pattern = rejected.c_str();
  session = reinterpret_cast<V8HostSession*>(1);
  if (v8host_client_create_session(&config, &session) != V8HOST_E_QUOTA ||
      session != nullptr)
    return Fail(detail, "32-KiB string not rejected/null");

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
      kind != -7 || relay_len != 3 ||
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
      empty_header.request_id <= h.request_id)
    return Fail(detail, "empty relay/request monotonicity");
  v8host_client_close_session(session);
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
    fake->Inbound(
        EventFrame(MessageType::RESULT, start.session_id, start.run_id));
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

  fake->Inbound(EventFrame(MessageType::RESULT, start.session_id, start.run_id));
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
  FrameHeader close_header;
  const auto close_frame = fake->Frame(after_close - 1);
  DecodeAndValidateFrame(close_frame.data(), close_frame.size(), &close_header);
  Drain();
  return (ok && after_close == before + 1 &&
          close_header.type == MessageType::CLOSE_SESSION) ||
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
  const std::vector<TestCase> tests = {
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
      {"delivery", "terminal-then-late-ack-relay", LateTrafficAfterTerminal},
      {"protocol", "wrong-conn-session-run-correlation",
       CorrelationMismatchDisconnects},
      {"protocol", "wrong-request-id-ack-error", UnknownRequestIdDisconnects},
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
  return v8host::test::RunTests(argc, argv, tests);
}
