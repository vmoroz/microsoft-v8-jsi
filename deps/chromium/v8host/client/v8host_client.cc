// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_client.h"

#include "v8host_client_transport.h"
#include "v8host_dispatcher.h"
#include "v8host_protocol.h"
#include "v8host_protocol_messages.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifdef ERROR
#undef ERROR
#endif

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace v8host::client {
class ClientConnection;
}

struct V8HostSession;

struct V8HostRun {
  V8HostSession* session = nullptr;
  uint32_t run_id = 0;
  v8host::client::RunTerminalArbiter arbiter;
  std::atomic<bool> terminal_local{false};
};

struct FileRuleCopy {
  std::wstring pattern;
  int32_t readonly = 0;
};

struct SessionConfigCopy {
  int32_t broker_mode = 0;
  int32_t tier = 0;
  int32_t integrity = 0;
  int32_t delayed_integrity = 0;
  int32_t initial_token = 0;
  int32_t lockdown_token = 0;
  int32_t prohibit_dynamic_code = 0;
  std::vector<FileRuleCopy> file_rules;
  int32_t use_app_container = 0;
  int32_t low_privilege_app_container = 0;
  std::wstring app_container_profile_name;
  std::vector<std::wstring> capabilities;
};

struct V8HostSession {
  std::atomic<int> refcount{1};
  std::shared_ptr<v8host::client::ClientConnection> conn;
  uint32_t session_id = 0;
  SessionConfigCopy config;
  v8host::client::SessionDispatch* dispatch = nullptr;
  uint64_t dispatch_id = 0;
  std::mutex mutex;
  std::unordered_map<uint32_t, std::unique_ptr<V8HostRun>> runs;
  uint32_t next_run_id = 1;
  bool closed = false;

  void AddRef() { refcount.fetch_add(1, std::memory_order_relaxed); }
  void Release();
};

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace v8host::client {
namespace {

constexpr UINT kDestroySessionMessage = WM_APP + 0x1E;
constexpr UINT kStartTransportMessage = WM_APP + 0x1F;
void StartConnection(ClientConnection* connection);

HINSTANCE ModuleInstance() {
  return reinterpret_cast<HINSTANCE>(&__ImageBase);
}

#ifdef V8HOST_CLIENT_TESTING
extern std::atomic<void (*)()> g_initialize_after_dispatcher_hook;
#endif

class ClientRuntime {
 public:
  static ClientRuntime& Instance() {
    static ClientRuntime* const instance = new ClientRuntime();
    return *instance;
  }

  V8HostStatus Initialize() {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
      switch (state_) {
        case State::kReady:
          return V8HOST_OK;
        case State::kFailed:
          return V8HOST_E_INTERNAL;
        case State::kInitializing:
          cv_.wait(lock, [this] { return state_ != State::kInitializing; });
          continue;
        case State::kUninitialized:
          state_ = State::kInitializing;
          break;
      }
      break;
    }
    lock.unlock();

    V8HostStatus status = Dispatcher::Instance().Initialize();
    if (status == V8HOST_OK &&
        Dispatcher::Instance().callback_thread_id() != ::GetCurrentThreadId()) {
      status = V8HOST_E_INTERNAL;
    }
#ifdef V8HOST_CLIENT_TESTING
    if (status == V8HOST_OK) {
      void (*hook)() =
          g_initialize_after_dispatcher_hook.load(std::memory_order_acquire);
      if (hook != nullptr)
        hook();
    }
#endif
    if (status == V8HOST_OK)
      status = CreateLifecycleWindow();

    lock.lock();
    state_ = status == V8HOST_OK ? State::kReady : State::kFailed;
    initialized_.store(status == V8HOST_OK, std::memory_order_release);
    cv_.notify_all();
    return status;
  }

  uint32_t lifecycle_thread_id() const {
    return lifecycle_thread_id_.load(std::memory_order_acquire);
  }

  uint32_t last_delete_thread_id() const {
    return last_delete_thread_id_.load(std::memory_order_acquire);
  }

 private:
  enum class State : uint8_t {
    kUninitialized,
    kInitializing,
    kReady,
    kFailed
  };

  V8HostStatus CreateLifecycleWindow() {
    class_name_ =
        L"V8HostClientLifecycle_" + std::to_wstring(reinterpret_cast<uintptr_t>(this));
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &WindowProc;
    wc.hInstance = ModuleInstance();
    wc.lpszClassName = class_name_.c_str();
    atom_ = ::RegisterClassExW(&wc);
    if (atom_ == 0)
      return V8HOST_E_INTERNAL;
    hwnd_ = ::CreateWindowExW(0, class_name_.c_str(), L"", 0, 0, 0, 0, 0,
                              HWND_MESSAGE, nullptr, ModuleInstance(), nullptr);
    if (hwnd_ == nullptr) {
      ::UnregisterClassW(class_name_.c_str(), ModuleInstance());
      atom_ = 0;
      return V8HOST_E_INTERNAL;
    }
    lifecycle_thread_id_.store(::GetCurrentThreadId(),
                               std::memory_order_release);
    return V8HOST_OK;
  }

 public:
  bool ScheduleStart(std::shared_ptr<ClientConnection> connection) {
    auto* pending = new (std::nothrow) std::shared_ptr<ClientConnection>(std::move(connection));
    if (!pending) return false;
    if (::PostMessageW(hwnd_, kStartTransportMessage, reinterpret_cast<WPARAM>(pending), 0)) return true;
    delete pending;
    return false;
  }

  bool IsInitialized() const {
    return initialized_.load(std::memory_order_acquire);
  }

  void ScheduleSessionDelete(V8HostSession* session) {
    HWND hwnd = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      hwnd = hwnd_;
    }
    if (hwnd != nullptr &&
        ::PostMessageW(hwnd, kDestroySessionMessage,
                       reinterpret_cast<WPARAM>(session), 0)) {
      return;
    }
    // Initialization guarantees a live lifecycle window. If the OS refuses
    // the post, leaking is safer than cross-thread deletion during a callback.
  }

 private:
  static LRESULT CALLBACK WindowProc(HWND hwnd,
                                     UINT message,
                                     WPARAM wparam,
                                     LPARAM lparam) {
    if (message == kStartTransportMessage) {
      std::unique_ptr<std::shared_ptr<ClientConnection>> pending(
          reinterpret_cast<std::shared_ptr<ClientConnection>*>(wparam));
      StartConnection(pending->get());
      return 0;
    }
    if (message == kDestroySessionMessage) {
      Instance().last_delete_thread_id_.store(::GetCurrentThreadId(),
                                               std::memory_order_release);
      delete reinterpret_cast<V8HostSession*>(wparam);
      return 0;
    }
    return ::DefWindowProcW(hwnd, message, wparam, lparam);
  }

  std::mutex mutex_;
  std::condition_variable cv_;
  State state_ = State::kUninitialized;
  HWND hwnd_ = nullptr;
  ATOM atom_ = 0;
  std::wstring class_name_;
  std::atomic<bool> initialized_{false};
  std::atomic<uint32_t> lifecycle_thread_id_{0};
  std::atomic<uint32_t> last_delete_thread_id_{0};
};

#ifdef V8HOST_CLIENT_TESTING
std::atomic<ClientTransportFactory> g_test_factory{nullptr};
std::atomic<void (*)()> g_before_submission{nullptr}, g_admitted_submission{nullptr};
std::atomic<void (*)()> g_initialize_after_dispatcher_hook{nullptr};
std::atomic<void (*)(V8HostStatus)> g_inbound_status_observer{nullptr};
#endif

void ObserveInboundStatusForTesting(V8HostStatus status) {
#ifdef V8HOST_CLIENT_TESTING
  void (*observer)(V8HostStatus) =
      g_inbound_status_observer.load(std::memory_order_acquire);
  if (observer != nullptr)
    observer(status);
#else
  (void)status;
#endif
}

ClientTransport* CreateTransport(const TransportParams& params,
                                 ClientTransportDelegate* delegate) {
#ifdef V8HOST_CLIENT_TESTING
  ClientTransportFactory factory =
      g_test_factory.load(std::memory_order_acquire);
  return factory != nullptr ? factory(params, delegate) : nullptr;
#else
  return CreateRealPipeClientTransport(params, delegate);
#endif
}

bool CountPairValid(const void* pointer, size_t count) {
  return (pointer == nullptr) == (count == 0);
}

V8HostStatus WideToUtf8(const wchar_t* text,
                        bool allow_null,
                        std::string* out) {
  out->clear();
  if (text == nullptr)
    return allow_null ? V8HOST_OK : V8HOST_E_INVALID_ARG;
  const size_t chars = std::wcslen(text);
  if (chars == 0)
    return V8HOST_OK;
  if (chars > static_cast<size_t>(INT_MAX))
    return V8HOST_E_QUOTA;
  const int bytes = ::WideCharToMultiByte(
      CP_UTF8, WC_ERR_INVALID_CHARS, text, static_cast<int>(chars), nullptr, 0,
      nullptr, nullptr);
  if (bytes <= 0)
    return V8HOST_E_INVALID_ARG;
  if (static_cast<uint32_t>(bytes) > protocol::kMaxStringBytes)
    return V8HOST_E_QUOTA;
  out->resize(bytes);
  if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text,
                            static_cast<int>(chars), out->data(), bytes, nullptr,
                            nullptr) != bytes) {
    out->clear();
    return V8HOST_E_INVALID_ARG;
  }
  return V8HOST_OK;
}

bool IsBareFilename(const std::wstring& value) {
  return !value.empty() && value != L"." &&
         value.find(L"..") == std::wstring::npos &&
         value.find_first_of(L"\\/:") == std::wstring::npos;
}

V8HostStatus MapStatus(protocol::StatusCode status) {
  switch (status) {
    case protocol::StatusCode::OK:
      return V8HOST_OK;
    case protocol::StatusCode::ERROR_PROTOCOL:
      return V8HOST_E_PROTOCOL;
    case protocol::StatusCode::ERROR_VERSION:
      return V8HOST_E_VERSION;
    case protocol::StatusCode::ERROR_QUOTA:
      return V8HOST_E_QUOTA;
    case protocol::StatusCode::ERROR_BAD_STATE:
      return V8HOST_E_INVALID_STATE;
    case protocol::StatusCode::ERROR_INTERNAL:
      return V8HOST_E_INTERNAL;
    case protocol::StatusCode::ERROR_PROFILE_ALREADY_BOUND:
      return V8HOST_E_PROFILE_ALREADY_BOUND;
    case protocol::StatusCode::ERROR_UNSUPPORTED_MESSAGE:
    case protocol::StatusCode::ERROR_STALE_REQUEST:
      return V8HOST_E_PROTOCOL;
  }
  return V8HOST_E_INTERNAL;
}

enum class PendingType { kCreate, kStart, kCancel, kClose };
struct PendingControl {
  PendingType type;
  uint32_t session_id;
  uint32_t run_id;
};

}  // namespace

class ClientConnection final
    : public ClientTransportDelegate,
      public std::enable_shared_from_this<ClientConnection> {
 public:
  ~ClientConnection() override {
    if (transport_ != nullptr)
      transport_->Close();
  }

  V8HostStatus Initialize(int32_t broker_mode) {
    TransportParams params;
    params.broker_mode = broker_mode;
    std::vector<wchar_t> path(256);
    for (;;) {
      const DWORD len = ::GetModuleFileNameW(ModuleInstance(), path.data(),
                                             static_cast<DWORD>(path.size()));
      if (!len) return V8HOST_E_CONNECT;
      if (len < path.size()) {
        params.payload_directory.assign(path.data(), len);
        const size_t slash = params.payload_directory.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return V8HOST_E_CONNECT;
        params.payload_directory.resize(slash);
        break;
      }
      if (path.size() >= 32768) return V8HOST_E_CONNECT;
      path.resize((std::min)(path.size() * 2, size_t{32768}));
    }
    transport_.reset(CreateTransport(params, this));
    if (!transport_)
      return V8HOST_E_NO_MEMORY;
    return V8HOST_OK;
  }

  void StartTransport() {
    if (transport_->Start(shared_from_this()) != V8HOST_OK)
      OnDisconnect(TransportDisconnect::kConnectFailed);
  }

  uint32_t AllocateSessionId() { return 1; }
  void TerminalizeExhaustion() {
    if (exhausted_.load(std::memory_order_acquire))
      OnDisconnect(TransportDisconnect::kProtocolError);
  }
#ifdef V8HOST_CLIENT_TESTING
  void SetRequestId(uint32_t id) {
    std::lock_guard<std::mutex> lock(submission_mutex_);
    next_request_id_ = id;
  }
#endif

  template <typename Builder>
  V8HostStatus SubmitControl(PendingControl pending, Builder build) {
#ifdef V8HOST_CLIENT_TESTING
    if (auto hook = g_before_submission.load(std::memory_order_acquire)) hook();
#endif
    // Order: session -> submission -> pending; callbacks never take submission.
    std::lock_guard<std::mutex> order(submission_mutex_);
    if (disconnected_.load(std::memory_order_acquire))
      return V8HOST_E_CONNECT;
    if (next_request_id_ == UINT32_MAX) {
      exhausted_.store(true, std::memory_order_release);
      return V8HOST_E_QUOTA;
    }
    const uint32_t id = next_request_id_++;
    V8HostStatus status = ReservePending(id, pending);
    if (status != V8HOST_OK)
      return status;
    protocol::FrameHeader header;
    header.version_major = protocol::kWireVersionMajor;
    header.version_minor = protocol::kWireVersionMinor;
    header.flags = protocol::kFlagMustUnderstand;
    header.conn_id = conn_id();
    header.session_id = pending.session_id;
    header.run_id = pending.run_id;
    header.request_id = id;
#ifdef V8HOST_CLIENT_TESTING
    if (auto hook = g_admitted_submission.load(std::memory_order_acquire)) hook();
#endif
    status = Send(build(header));
    if (status != V8HOST_OK)
      RemovePending(id);
    return status;
  }

  void OnConnected(uint32_t, uint16_t major, uint16_t minor) override {
    selected_major_.store(major, std::memory_order_release);
    selected_minor_.store(minor, std::memory_order_release);
  }

  uint32_t conn_id() const {
    return transport_ != nullptr ? transport_->conn_id() : 0;
  }

  void RegisterSession(V8HostSession* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[session->session_id] = session;
  }

  void UnregisterSession(uint32_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(id);
  }

  V8HostStatus ReservePending(uint32_t request_id, PendingControl pending) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pending_.size() >= protocol::kMaxControlQueueRequests)
      return V8HOST_E_QUOTA;
    pending_[request_id] = pending;
    return V8HOST_OK;
  }

  void RemovePending(uint32_t request_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.erase(request_id);
  }

  V8HostStatus Send(const std::vector<uint8_t>& frame) {
    if (!transport_)
      return V8HOST_E_CONNECT;
    return transport_->SendFrame(frame.data(), frame.size());
  }

  void CloseTransport() {
    if (transport_)
      transport_->Close();
  }

  void OnInboundFrame(const uint8_t* bytes, size_t len) override {
    protocol::FrameHeader header;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (protocol::DecodeAndValidateFrame(bytes, len, &header, &payload,
                                         &payload_len) !=
            protocol::DecodeStatus::kOk ||
        header.version_major != selected_major_.load(std::memory_order_acquire) ||
        header.version_minor != selected_minor_.load(std::memory_order_acquire) ||
        header.conn_id != conn_id()) {
      OnDisconnect(TransportDisconnect::kProtocolError);
      ObserveInboundStatusForTesting(V8HOST_E_PROTOCOL);
      return;
    }

    if (header.type == protocol::MessageType::ACK ||
        header.type == protocol::MessageType::ERROR) {
      if (header.type == protocol::MessageType::ERROR && header.request_id == 0)
        RouteRelayQuota(header, payload, payload_len);
      else
        RouteControl(header, payload, payload_len);
      return;
    }

    V8HostSession* session = AcquireSession(header.session_id);
    if (session == nullptr) {
      ObserveInboundStatusForTesting(V8HOST_E_INVALID_STATE);
      return;
    }
    RouteSessionFrame(session, header, payload, payload_len);
    session->Release();
  }

  void OnDisconnect(TransportDisconnect reason) override {
    bool expected = false;
    if (!disconnected_.compare_exchange_strong(expected, true,
                                                std::memory_order_acq_rel)) {
      return;
    }
    CloseTransport();
    const V8HostStatus status =
        reason == TransportDisconnect::kProtocolError
            ? V8HOST_E_PROTOCOL
            : (reason == TransportDisconnect::kConnectFailed
                   ? V8HOST_E_CONNECT
                   : V8HOST_E_BROKER_LOST);
    std::vector<V8HostSession*> sessions;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      sessions.reserve(sessions_.size());
      for (const auto& entry : sessions_) {
        entry.second->AddRef();
        sessions.push_back(entry.second);
      }
      pending_.clear();
    }
    for (V8HostSession* session : sessions) {
      std::vector<V8HostRun*> runs;
      {
        std::lock_guard<std::mutex> lock(session->mutex);
        runs.reserve(session->runs.size());
        for (const auto& entry : session->runs) {
          V8HostRun* run = entry.second.get();
          if (!run->terminal_local.exchange(true, std::memory_order_acq_rel))
            runs.push_back(run);
        }
      }
      for (V8HostRun* run : runs) {
        Dispatcher::Instance().PostRunEvent(
            session->dispatch_id, run, &run->arbiter, true,
            reason == TransportDisconnect::kBrokerLost
                ? V8HOST_RUN_EVENT_BROKER_LOST
                : V8HOST_RUN_EVENT_FAILED,
            status);
      }
      Dispatcher::Instance().PostSessionState(
          session->dispatch_id, V8HOST_SESSION_STATE_CLOSED, status);
      Dispatcher::Instance().PostDisconnect(session->dispatch_id);
      session->Release();
    }
  }

 private:
  V8HostSession* AcquireSession(uint32_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = sessions_.find(id);
    if (it == sessions_.end())
      return nullptr;
    it->second->AddRef();
    return it->second;
  }

  V8HostRun* FindRun(V8HostSession* session, uint32_t run_id) {
    std::lock_guard<std::mutex> lock(session->mutex);
    const auto it = session->runs.find(run_id);
    return it == session->runs.end() ? nullptr : it->second.get();
  }

  void MarkAndPostTerminal(V8HostSession* session,
                           V8HostRun* run,
                           int32_t event,
                           V8HostStatus status) {
    {
      std::lock_guard<std::mutex> lock(session->mutex);
      if (run->terminal_local.exchange(true, std::memory_order_acq_rel))
        return;
    }
    Dispatcher::Instance().PostRunEvent(session->dispatch_id, run, &run->arbiter,
                                        true, event, status);
  }

  void RouteRelayQuota(const protocol::FrameHeader& header,
                       const uint8_t* payload, size_t payload_len) {
    protocol::ErrorPayload error;
    if (!header.session_id || !header.run_id ||
        !protocol::DecodeErrorPayload(payload, payload_len, &error) ||
        error.status_code != protocol::StatusCode::ERROR_QUOTA) {
      OnDisconnect(TransportDisconnect::kProtocolError);
      return;
    }
    V8HostSession* session = AcquireSession(header.session_id);
    if (!session) {
      OnDisconnect(TransportDisconnect::kProtocolError);
      return;
    }
    V8HostRun* run = FindRun(session, header.run_id);
    if (run)
      MarkAndPostTerminal(session, run, V8HOST_RUN_EVENT_FAILED, V8HOST_E_QUOTA);
    session->Release();
    if (!run) OnDisconnect(TransportDisconnect::kProtocolError);
  }

  void RouteControl(const protocol::FrameHeader& header,
                    const uint8_t* payload,
                    size_t payload_len) {
    PendingControl pending{PendingType::kCreate, 0, 0};
    bool correlation_valid = false;
    bool consumed_duplicate = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      const auto it = pending_.find(header.request_id);
      if (it != pending_.end()) {
        pending = it->second;
        correlation_valid =
            header.session_id == pending.session_id &&
            header.run_id == pending.run_id;
        if (correlation_valid) {
          pending_.erase(it);
          if (consumed_requests_.size() == protocol::kDuplicateCacheSize) {
            consumed_request_map_.erase(consumed_requests_.front());
            consumed_requests_.pop_front();
          }
          consumed_requests_.push_back(header.request_id);
          consumed_request_map_[header.request_id] = pending;
        }
      } else {
        const auto consumed = consumed_request_map_.find(header.request_id);
        consumed_duplicate =
            consumed != consumed_request_map_.end() &&
            header.session_id == consumed->second.session_id &&
            header.run_id == consumed->second.run_id;
      }
    }
    if (consumed_duplicate)
      return;
    if (!correlation_valid) {
      OnDisconnect(TransportDisconnect::kProtocolError);
      return;
    }
    V8HostSession* session = AcquireSession(pending.session_id);
    if (session == nullptr)
      return;
    if (header.type == protocol::MessageType::ACK) {
      protocol::AckPayload ack;
      if (!protocol::DecodeAckPayload(payload, payload_len, &ack)) {
        session->Release();
        OnDisconnect(TransportDisconnect::kProtocolError);
        return;
      }
      if (pending.type == PendingType::kStart) {
        std::lock_guard<std::mutex> lock(session->mutex);
        const auto it = session->runs.find(pending.run_id);
        if (it != session->runs.end() &&
            !it->second->terminal_local.load(std::memory_order_acquire)) {
          V8HostRun* run = it->second.get();
          Dispatcher::Instance().PostRunEvent(
              session->dispatch_id, run, &run->arbiter, false,
              V8HOST_RUN_EVENT_STARTED, V8HOST_OK);
        }
      }
    } else {
      protocol::ErrorPayload error;
      if (!protocol::DecodeErrorPayload(payload, payload_len, &error)) {
        session->Release();
        OnDisconnect(TransportDisconnect::kProtocolError);
        return;
      }
      const V8HostStatus status = MapStatus(error.status_code);
      if (pending.run_id != 0) {
        V8HostRun* run = FindRun(session, pending.run_id);
        if (run != nullptr)
          MarkAndPostTerminal(session, run, V8HOST_RUN_EVENT_FAILED, status);
      } else {
        Dispatcher::Instance().PostSessionState(
            session->dispatch_id, V8HOST_SESSION_STATE_CLOSED, status);
      }
    }
    session->Release();
  }

  void RouteSessionFrame(V8HostSession* session,
                         const protocol::FrameHeader& header,
                         const uint8_t* payload,
                         size_t payload_len) {
    switch (header.type) {
      case protocol::MessageType::SESSION_READY:
        ObserveInboundStatusForTesting(
            Dispatcher::Instance().PostSessionState(
                session->dispatch_id, V8HOST_SESSION_STATE_READY, V8HOST_OK));
        return;
      case protocol::MessageType::STARTUP_READY:
        Dispatcher::Instance().PostSessionState(
            session->dispatch_id,
            V8HOST_SESSION_STATE_WORKER_STARTUP_READY, V8HOST_OK);
        return;
      case protocol::MessageType::SECURITY_READY:
        Dispatcher::Instance().PostSessionState(
            session->dispatch_id,
            V8HOST_SESSION_STATE_WORKER_SECURITY_READY, V8HOST_OK);
        return;
      case protocol::MessageType::RELAY_FROM_WORKER: {
        int32_t kind = 0;
        const uint8_t* body = nullptr;
        size_t body_len = 0;
        if (!protocol::DecodeRelayPayload(payload, payload_len, &kind, &body,
                                          &body_len))
          break;
        std::lock_guard<std::mutex> lock(session->mutex);
        const auto it = session->runs.find(header.run_id);
        if (it == session->runs.end() ||
            it->second->terminal_local.load(std::memory_order_acquire))
          return;
        return static_cast<void>(Dispatcher::Instance().PostRelay(
            session->dispatch_id, it->second.get(), kind, body, body_len));
      }
      case protocol::MessageType::RESULT: {
        protocol::ResultPayload result;
        if (!protocol::DecodeResultPayload(payload, payload_len, &result))
          break;  // malformed -> protocol-error disconnect (fail-closed)
        V8HostRun* run = FindRun(session, header.run_id);
        if (run != nullptr) {
          const int32_t event =
              result.disposition == protocol::ResultDisposition::kCancelled
                  ? V8HOST_RUN_EVENT_CANCELLED
                  : V8HOST_RUN_EVENT_COMPLETED;
          MarkAndPostTerminal(session, run, event, V8HOST_OK);
        }
        return;
      }
      case protocol::MessageType::RUN_ERROR: {
        V8HostRun* run = FindRun(session, header.run_id);
        if (run == nullptr)
          return;
        protocol::ErrorPayload error;
        const V8HostStatus status =
            protocol::DecodeErrorPayload(payload, payload_len, &error)
                ? MapStatus(error.status_code)
                : V8HOST_E_PROTOCOL;
        MarkAndPostTerminal(session, run, V8HOST_RUN_EVENT_FAILED, status);
        return;
      }
      case protocol::MessageType::WORKER_EXIT: {
        std::vector<V8HostRun*> runs;
        {
          std::lock_guard<std::mutex> lock(session->mutex);
          for (const auto& entry : session->runs) {
            if (!entry.second->terminal_local.exchange(
                    true, std::memory_order_acq_rel)) {
              runs.push_back(entry.second.get());
            }
          }
        }
        for (V8HostRun* run : runs) {
          Dispatcher::Instance().PostRunEvent(
              session->dispatch_id, run, &run->arbiter, true,
              V8HOST_RUN_EVENT_WORKER_EXITED, V8HOST_E_RUN_TERMINAL);
        }
        Dispatcher::Instance().PostSessionState(
            session->dispatch_id, V8HOST_SESSION_STATE_CLOSED,
            V8HOST_E_RUN_TERMINAL);
        return;
      }
      default:
        break;
    }
    OnDisconnect(TransportDisconnect::kProtocolError);
  }

  std::mutex mutex_;
  std::unordered_map<uint32_t, V8HostSession*> sessions_;
  std::unordered_map<uint32_t, PendingControl> pending_;
  std::deque<uint32_t> consumed_requests_;
  std::unordered_map<uint32_t, PendingControl> consumed_request_map_;
  std::unique_ptr<ClientTransport> transport_;
  std::mutex submission_mutex_;
  uint32_t next_request_id_ = 2;
  std::atomic<uint16_t> selected_major_{protocol::kWireVersionMajor};
  std::atomic<uint16_t> selected_minor_{protocol::kWireVersionMinor};
  std::atomic<bool> disconnected_{false};
  std::atomic<bool> exhausted_{false};
};

namespace {
void StartConnection(ClientConnection* connection) { connection->StartTransport(); }
}
#ifdef V8HOST_CLIENT_TESTING
void SetSubmissionHooksForTesting(void (*before)(), void (*admitted)()) {
  g_before_submission.store(before, std::memory_order_release);
  g_admitted_submission.store(admitted, std::memory_order_release);
}
V8HostStatus SubmitCancelForTesting(V8HostSession* session, uint32_t run) {
  return session->conn->SubmitControl({PendingType::kCancel, session->session_id, run},
      [](const auto& header) { return protocol::BuildCancelRunFrame(header); });
}
void SetIdsForTesting(V8HostSession* session, uint32_t request, uint32_t run) {
  std::lock_guard<std::mutex> lock(session->mutex);
  session->conn->SetRequestId(request);
  session->next_run_id = run;
}
void SetTransportFactoryForTesting(ClientTransportFactory factory) {
  g_test_factory.store(factory, std::memory_order_release);
}

void SetInitializeAfterDispatcherHookForTesting(void (*hook)()) {
  g_initialize_after_dispatcher_hook.store(hook, std::memory_order_release);
}

uint32_t LifecycleThreadIdForTesting() {
  return ClientRuntime::Instance().lifecycle_thread_id();
}

uint32_t LastSessionDeleteThreadIdForTesting() {
  return ClientRuntime::Instance().last_delete_thread_id();
}

void SetInboundStatusObserverForTesting(void (*observer)(V8HostStatus)) {
  g_inbound_status_observer.store(observer, std::memory_order_release);
}
#endif

namespace {

protocol::FrameHeader MakeHeader(ClientConnection* conn,
                                 uint32_t session_id,
                                 uint32_t run_id,
                                 uint32_t request_id,
                                 bool control) {
  protocol::FrameHeader header;
  header.version_major = protocol::kWireVersionMajor;
  header.version_minor = protocol::kWireVersionMinor;
  header.flags = control ? protocol::kFlagMustUnderstand : 0;
  header.conn_id = conn->conn_id();
  header.session_id = session_id;
  header.run_id = run_id;
  header.request_id = request_id;
  return header;
}

V8HostStatus ValidateAndCopyConfig(const V8HostSessionConfig* config,
                                   SessionConfigCopy* copy) {
  if (config == nullptr)
    return V8HOST_E_INVALID_ARG;
  if (config->struct_size < sizeof(V8HostSessionConfig))
    return V8HOST_E_STRUCT_SIZE;
  if ((config->broker_mode != V8HOST_BROKER_DEDICATED &&
       config->broker_mode != V8HOST_BROKER_SHARED) ||
      (config->tier != V8HOST_TIER_UNTRUSTED &&
       config->tier != V8HOST_TIER_TRUSTED)) {
    return V8HOST_E_INVALID_ARG;
  }
  if (config->file_rule_count > protocol::kMaxFileRules ||
      config->capability_count > protocol::kMaxCapabilities) {
    return V8HOST_E_QUOTA;
  }
  if (!CountPairValid(config->file_rules, config->file_rule_count) ||
      !CountPairValid(config->capabilities, config->capability_count)) {
    return V8HOST_E_INVALID_ARG;
  }
  const bool app_container = config->use_app_container != 0;
  const bool has_profile = config->app_container_profile_name != nullptr &&
                           config->app_container_profile_name[0] != L'\0';
  if ((app_container && !has_profile) ||
      (!app_container && (has_profile || config->capability_count != 0)) ||
      (config->low_privilege_app_container != 0 && !app_container)) {
    return V8HOST_E_INVALID_ARG;
  }

  std::string utf8;
  for (size_t i = 0; i < config->file_rule_count; ++i) {
    const V8HostFileRule& rule = config->file_rules[i];
    V8HostStatus status = WideToUtf8(rule.pattern, false, &utf8);
    if (status != V8HOST_OK)
      return status;
  }
  V8HostStatus status =
      WideToUtf8(config->app_container_profile_name, true, &utf8);
  if (status != V8HOST_OK)
    return status;
  for (size_t i = 0; i < config->capability_count; ++i) {
    status = WideToUtf8(config->capabilities[i], false, &utf8);
    if (status != V8HOST_OK || utf8.empty())
      return status == V8HOST_OK ? V8HOST_E_INVALID_ARG : status;
  }

  copy->broker_mode = config->broker_mode;
  copy->tier = config->tier;
  copy->integrity = config->integrity;
  copy->delayed_integrity = config->delayed_integrity;
  copy->initial_token = config->initial_token;
  copy->lockdown_token = config->lockdown_token;
  copy->prohibit_dynamic_code = config->prohibit_dynamic_code;
  copy->use_app_container = config->use_app_container;
  copy->low_privilege_app_container = config->low_privilege_app_container;
  if (config->app_container_profile_name != nullptr)
    copy->app_container_profile_name = config->app_container_profile_name;
  copy->file_rules.reserve(config->file_rule_count);
  for (size_t i = 0; i < config->file_rule_count; ++i) {
    copy->file_rules.push_back(
        {config->file_rules[i].pattern, config->file_rules[i].readonly});
  }
  copy->capabilities.reserve(config->capability_count);
  for (size_t i = 0; i < config->capability_count; ++i)
    copy->capabilities.emplace_back(config->capabilities[i]);
  return V8HOST_OK;
}

protocol::CreateSessionPayload MakeCreatePayload(
    const SessionConfigCopy& config) {
  protocol::CreateSessionPayload payload;
  payload.broker_mode = config.broker_mode;
  payload.tier = config.tier;
  payload.integrity = config.integrity;
  payload.delayed_integrity = config.delayed_integrity;
  payload.initial_token = config.initial_token;
  payload.lockdown_token = config.lockdown_token;
  payload.prohibit_dynamic_code = config.prohibit_dynamic_code != 0;
  payload.use_app_container = config.use_app_container != 0;
  payload.low_privilege_app_container =
      config.low_privilege_app_container != 0;
  WideToUtf8(config.app_container_profile_name.c_str(), true,
             &payload.app_container_profile);
  for (const FileRuleCopy& rule : config.file_rules) {
    protocol::FileRule wire_rule;
    wire_rule.readonly = rule.readonly != 0;
    WideToUtf8(rule.pattern.c_str(), false, &wire_rule.pattern);
    payload.file_rules.push_back(std::move(wire_rule));
  }
  for (const std::wstring& capability : config.capabilities) {
    std::string wire;
    WideToUtf8(capability.c_str(), false, &wire);
    payload.capabilities.push_back(std::move(wire));
  }
  return payload;
}

}  // namespace
}  // namespace v8host::client

void V8HostSession::Release() {
  if (refcount.fetch_sub(1, std::memory_order_acq_rel) == 1)
    v8host::client::ClientRuntime::Instance().ScheduleSessionDelete(this);
}

extern "C" {

V8HostStatus V8HOST_CALL v8host_client_initialize(void) {
  return v8host::client::ClientRuntime::Instance().Initialize();
}

V8HostStatus V8HOST_CALL v8host_client_create_session(
    const V8HostSessionConfig* config,
    V8HostSession** out_session) {
  if (out_session == nullptr)
    return V8HOST_E_INVALID_ARG;
  *out_session = nullptr;
  if (!v8host::client::ClientRuntime::Instance().IsInitialized())
    return V8HOST_E_NOT_INITIALIZED;

  SessionConfigCopy config_copy;
  V8HostStatus status =
      v8host::client::ValidateAndCopyConfig(config, &config_copy);
  if (status != V8HOST_OK)
    return status;

  std::shared_ptr<v8host::client::ClientConnection> connection(
      new (std::nothrow) v8host::client::ClientConnection());
  if (!connection)
    return V8HOST_E_NO_MEMORY;
  status = connection->Initialize(config_copy.broker_mode);
  if (status != V8HOST_OK)
    return status;

  std::unique_ptr<V8HostSession> session(new (std::nothrow) V8HostSession());
  if (!session)
    return V8HOST_E_NO_MEMORY;
  session->conn = connection;
  session->session_id = connection->AllocateSessionId();
  session->config = std::move(config_copy);
  session->dispatch = v8host::client::SessionDispatch::Create(
      &v8host::client::Dispatcher::Instance(), session.get(),
      V8HOST_SESSION_STATE_CLOSED);
  if (session->dispatch == nullptr)
    return V8HOST_E_NO_MEMORY;
  session->dispatch_id = session->dispatch->id();
  connection->RegisterSession(session.get());

  status = connection->SubmitControl(
      {v8host::client::PendingType::kCreate, session->session_id, 0},
      [&](const auto& header) {
        return v8host::protocol::BuildCreateSessionFrame(
            header, v8host::client::MakeCreatePayload(session->config));
      });
  if (status != V8HOST_OK) {
    connection->UnregisterSession(session->session_id);
    session->dispatch->CloseAndRelease();
    session->dispatch = nullptr;
    return status;
  }
  if (!v8host::client::ClientRuntime::Instance().ScheduleStart(connection)) {
    connection->UnregisterSession(session->session_id);
    session->dispatch->CloseAndRelease();
    session->dispatch = nullptr;
    return V8HOST_E_CONNECT;
  }

  *out_session = session.release();
  return V8HOST_OK;
}

V8HostStatus V8HOST_CALL v8host_client_set_callbacks(
    V8HostSession* session,
    const V8HostCallbacks* callbacks) {
  if (session == nullptr || callbacks == nullptr)
    return V8HOST_E_INVALID_ARG;
  if (callbacks->struct_size < sizeof(V8HostCallbacks))
    return V8HOST_E_STRUCT_SIZE;
  return v8host::client::Dispatcher::Instance().SetCallbacks(
      session->dispatch_id, callbacks);
}

V8HostStatus V8HOST_CALL v8host_client_start_run(
    V8HostSession* session,
    const V8HostRunInputs* inputs,
    V8HostRun** out_run) {
  if (out_run == nullptr)
    return V8HOST_E_INVALID_ARG;
  *out_run = nullptr;
  if (session == nullptr || inputs == nullptr)
    return V8HOST_E_INVALID_ARG;
  if (inputs->struct_size < sizeof(V8HostRunInputs))
    return V8HOST_E_STRUCT_SIZE;
  if (inputs->tier_override < -1 || inputs->tier_override > 1)
    return V8HOST_E_INVALID_ARG;
  const int32_t effective_tier =
      inputs->tier_override == -1 ? session->config.tier : inputs->tier_override;
  if (effective_tier == V8HOST_TIER_TRUSTED &&
      session->config.prohibit_dynamic_code != 0) {
    return V8HOST_E_INVALID_ARG;
  }
  if (!v8host::client::CountPairValid(inputs->payload, inputs->payload_len))
    return V8HOST_E_INVALID_ARG;

  std::wstring engine =
      inputs->engine_dll_override != nullptr ? inputs->engine_dll_override : L"";
  std::wstring snapshot = inputs->startup_snapshot_path != nullptr
                              ? inputs->startup_snapshot_path
                              : L"";
  if (inputs->engine_dll_override != nullptr &&
      !v8host::client::IsBareFilename(engine)) {
    return V8HOST_E_INVALID_ARG;
  }
  if (inputs->startup_snapshot_path != nullptr && snapshot.empty())
    return V8HOST_E_INVALID_ARG;
  std::string engine_utf8;
  std::string snapshot_utf8;
  V8HostStatus status = v8host::client::WideToUtf8(
      inputs->engine_dll_override, true, &engine_utf8);
  if (status != V8HOST_OK)
    return status;
  status = v8host::client::WideToUtf8(inputs->startup_snapshot_path, true,
                                     &snapshot_utf8);
  if (status != V8HOST_OK)
    return status;
  if (inputs->payload_len > v8host::protocol::kMaxFramePayload)
    return V8HOST_E_QUOTA;
  const size_t variable_size = sizeof(uint32_t) + engine_utf8.size() +
                               sizeof(uint32_t) + snapshot_utf8.size() +
                               inputs->payload_len;
  if (v8host::protocol::kStartRunFixedSize + variable_size >
      v8host::protocol::kMaxFramePayload) {
    return V8HOST_E_QUOTA;
  }

  std::unique_lock<std::mutex> lock(session->mutex);
  if (session->closed)
    return V8HOST_E_INVALID_STATE;
  size_t live_runs = 0;
  for (const auto& entry : session->runs) {
    if (!entry.second->terminal_local.load(std::memory_order_acquire))
      ++live_runs;
  }
  if (live_runs >= v8host::protocol::kMaxInFlightRunsPerSession)
    return V8HOST_E_QUOTA;

  std::unique_ptr<V8HostRun> run(new (std::nothrow) V8HostRun());
  if (!run)
    return V8HOST_E_NO_MEMORY;
  run->session = session;
  if (session->next_run_id == UINT32_MAX) {
    lock.unlock();
    session->conn->OnDisconnect(v8host::client::TransportDisconnect::kProtocolError);
    return V8HOST_E_QUOTA;
  }
  run->run_id = session->next_run_id++;
  V8HostRun* run_handle = run.get();

  v8host::protocol::StartRunPayload payload;
  payload.tier_override = inputs->tier_override;
  payload.has_engine_override = inputs->engine_dll_override != nullptr;
  payload.has_snapshot = inputs->startup_snapshot_path != nullptr;
  payload.engine_filename = std::move(engine_utf8);
  payload.snapshot_path = std::move(snapshot_utf8);
  if (inputs->payload_len != 0) {
    const auto* bytes = static_cast<const uint8_t*>(inputs->payload);
    payload.guest_payload.assign(bytes, bytes + inputs->payload_len);
  }
  session->runs.emplace(run->run_id, std::move(run));
  status = session->conn->SubmitControl(
      {v8host::client::PendingType::kStart, session->session_id, run_handle->run_id},
      [&](const auto& header) {
        return v8host::protocol::BuildStartRunFrame(header, payload);
      });
  if (status != V8HOST_OK) {
    session->runs.erase(run_handle->run_id);
    lock.unlock();
    session->conn->TerminalizeExhaustion();
    return status;
  }
  *out_run = run_handle;
  return V8HOST_OK;
}

V8HostStatus V8HOST_CALL v8host_client_post_message(
    V8HostRun* run,
    int32_t kind,
    const void* data,
    size_t len) {
  if (run == nullptr || !v8host::client::CountPairValid(data, len))
    return V8HOST_E_INVALID_ARG;
  if (len > v8host::protocol::kMaxFramePayload - sizeof(uint32_t))
    return V8HOST_E_QUOTA;
  if (run->terminal_local.load(std::memory_order_acquire))
    return V8HOST_E_RUN_TERMINAL;
  V8HostSession* session = run->session;
  std::unique_lock<std::mutex> lock(session->mutex);
  if (session->closed)
    return V8HOST_E_INVALID_STATE;
  if (run->terminal_local.load(std::memory_order_acquire))
    return V8HOST_E_RUN_TERMINAL;
  auto header = v8host::client::MakeHeader(
      session->conn.get(), session->session_id, run->run_id, 0, false);
  header.type = v8host::protocol::MessageType::RELAY_TO_WORKER;
  const auto frame = v8host::protocol::BuildRelayFrame(
      header, kind, static_cast<const uint8_t*>(data), len);
  const V8HostStatus send_status = session->conn->Send(frame);
  return send_status;
}

V8HostStatus V8HOST_CALL v8host_client_cancel_run(V8HostRun* run) {
  if (run == nullptr)
    return V8HOST_E_INVALID_ARG;
  if (run->terminal_local.load(std::memory_order_acquire))
    return V8HOST_E_RUN_TERMINAL;
  V8HostSession* session = run->session;
  std::unique_lock<std::mutex> lock(session->mutex);
  if (session->closed)
    return V8HOST_E_INVALID_STATE;
  if (run->terminal_local.load(std::memory_order_acquire))
    return V8HOST_E_RUN_TERMINAL;
  V8HostStatus status = session->conn->SubmitControl(
      {v8host::client::PendingType::kCancel, session->session_id, run->run_id},
      [](const auto& header) { return v8host::protocol::BuildCancelRunFrame(header); });
  lock.unlock();
  session->conn->TerminalizeExhaustion();
  return status;
}

void V8HOST_CALL v8host_client_close_session(V8HostSession* session) {
  if (session == nullptr)
    return;
  {
    std::lock_guard<std::mutex> lock(session->mutex);
    if (session->closed)
      return;
    session->closed = true;
    for (const auto& entry : session->runs)
      entry.second->terminal_local.store(true, std::memory_order_release);
  }
  session->conn->UnregisterSession(session->session_id);
  session->dispatch->CloseAndRelease();
  session->conn->SubmitControl(
      {v8host::client::PendingType::kClose, session->session_id, 0},
      [](const auto& header) { return v8host::protocol::BuildCloseSessionFrame(header); });
  session->conn->CloseTransport();
  session->Release();
}

}  // extern "C"
