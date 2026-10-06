// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_dispatcher.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstring>
#include <new>
#include <string>

// The current module (DLL or test exe); used as the window-class hInstance so
// registration/creation stay inside this module.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace v8host::client {
namespace {

// Private window message carrying a drain request. wParam is a SessionDispatch*
// with one reference held by the poster (released by DrainFromMessage).
constexpr UINT kDrainMessage = WM_APP + 0x1D;

HINSTANCE ModuleInstance() {
  return reinterpret_cast<HINSTANCE>(&__ImageBase);
}

LRESULT CALLBACK DispatchWndProc(HWND hwnd,
                                 UINT message,
                                 WPARAM wparam,
                                 LPARAM lparam) {
  if (message == kDrainMessage) {
    auto* session = reinterpret_cast<SessionDispatch*>(wparam);
    if (session)
      SessionDispatch::DrainFromMessage(session);
    return 0;
  }
  return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

std::atomic<int>& LiveCounter() {
  static std::atomic<int> counter{0};
  return counter;
}

// RAII holder for a counted SessionDispatch reference. The id-keyed producer API
// AddRef's the target under `sessions_mutex_` (so the lookup cannot race the
// object's destruction), then dispatches through this holder, which Releases the
// reference when it leaves scope.
class SessionRef {
 public:
  explicit SessionRef(SessionDispatch* session) : session_(session) {}
  ~SessionRef() {
    if (session_ != nullptr)
      session_->Release();
  }
  SessionRef(const SessionRef&) = delete;
  SessionRef& operator=(const SessionRef&) = delete;
  explicit operator bool() const { return session_ != nullptr; }
  SessionDispatch* operator->() const { return session_; }

 private:
  SessionDispatch* session_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

Dispatcher& Dispatcher::Instance() {
  // Intentionally leaked: the message-only window lives for the whole process,
  // so there is no safe time (and no correct thread) to run a destructor.
  static Dispatcher* const instance = new Dispatcher();
  return *instance;
}

Dispatcher::Dispatcher() = default;

Dispatcher::~Dispatcher() = default;

V8HostStatus Dispatcher::Initialize() {
  std::unique_lock<std::mutex> lock(init_mutex_);
  for (;;) {
    switch (state_) {
      case State::kReady:
        return V8HOST_OK;
      case State::kFailed:
        return V8HOST_E_INTERNAL;
      case State::kInitializing:
        // Another thread is creating the window. Wait without pumping: a
        // condition variable parks this thread until the first initializer
        // publishes a terminal state.
        init_cv_.wait(lock,
                      [this] { return state_ != State::kInitializing; });
        continue;
      case State::kUninitialized:
        state_ = State::kInitializing;
        // Release the lock across the Win32 work so racing callers can observe
        // kInitializing and wait on the condition variable.
        lock.unlock();
        const bool ok = CreateDispatchWindow();
        lock.lock();
        state_ = ok ? State::kReady : State::kFailed;
        init_cv_.notify_all();
        return ok ? V8HOST_OK : V8HOST_E_INTERNAL;
    }
  }
}

bool Dispatcher::CreateDispatchWindow() {
  // Captures the calling thread as the callback thread (design 9.1).
  thread_id_.store(::GetCurrentThreadId(), std::memory_order_release);

  // Unique per-instance class name so independent Dispatcher instances (e.g.
  // the process-global one plus any under test) never collide on registration.
  class_name_ = L"V8HostDispatch_" +
                std::to_wstring(reinterpret_cast<uintptr_t>(this));

  WNDCLASSEXW window_class = {};
  window_class.cbSize = sizeof(window_class);
  window_class.lpfnWndProc = &DispatchWndProc;
  window_class.hInstance = ModuleInstance();
  window_class.lpszClassName = class_name_.c_str();
  class_atom_ = ::RegisterClassExW(&window_class);
  if (class_atom_ == 0)
    return false;

  HWND hwnd = ::CreateWindowExW(0, class_name_.c_str(), L"", 0, 0, 0, 0, 0,
                                HWND_MESSAGE, nullptr, ModuleInstance(),
                                nullptr);
  if (hwnd == nullptr) {
    ::UnregisterClassW(class_name_.c_str(), ModuleInstance());
    class_atom_ = 0;
    return false;
  }

  hwnd_.store(hwnd, std::memory_order_release);
  ready_.store(true, std::memory_order_release);
  return true;
}

void Dispatcher::ShutdownForTesting() {
  HWND hwnd =
      reinterpret_cast<HWND>(hwnd_.exchange(nullptr, std::memory_order_acq_rel));
  ready_.store(false, std::memory_order_release);
  if (hwnd != nullptr)
    ::DestroyWindow(hwnd);  // must run on the creating (callback) thread
  if (class_atom_ != 0) {
    ::UnregisterClassW(class_name_.c_str(), ModuleInstance());
    class_atom_ = 0;
  }
}

bool Dispatcher::PostDrain(SessionDispatch* session) {
  HWND hwnd = reinterpret_cast<HWND>(hwnd_.load(std::memory_order_acquire));
  if (hwnd == nullptr)
    return false;
  return ::PostMessageW(hwnd, kDrainMessage,
                        reinterpret_cast<WPARAM>(session), 0) != 0;
}

// ---------------------------------------------------------------------------
// Dispatcher -- session registry + id-keyed producer API
// ---------------------------------------------------------------------------

uint64_t Dispatcher::AllocateSessionId() {
  return next_session_id_.fetch_add(1, std::memory_order_relaxed);
}

void Dispatcher::RegisterSession(uint64_t id, SessionDispatch* session) {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  sessions_[id] = session;
}

void Dispatcher::UnregisterSession(uint64_t id) {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  sessions_.erase(id);
}

SessionDispatch* Dispatcher::AcquireSession(uint64_t id) {
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  auto it = sessions_.find(id);
  if (it == sessions_.end())
    return nullptr;
  // AddRef before releasing sessions_mutex_: UnregisterSession erases under the
  // same lock, so we either AddRef before the owner's erase (the object stays
  // alive for this post) or never get here (find fails after the erase). The
  // returned reference is owned by the caller.
  it->second->AddRef();
  return it->second;
}

// Id-keyed producer API: resolve the id to a counted reference (AddRef'd under
// sessions_mutex_), release that lock, dispatch to the per-session method, then
// Release on scope exit. An unknown id (never created or already closed) drops
// with V8HOST_E_INVALID_STATE -- no freed object is ever dereferenced.
V8HostStatus Dispatcher::PostSessionState(uint64_t id,
                                          int32_t state,
                                          V8HostStatus status) {
  SessionRef session(AcquireSession(id));
  if (!session)
    return V8HOST_E_INVALID_STATE;
  return session->PostSessionState(state, status);
}

V8HostStatus Dispatcher::PostRunEvent(uint64_t id,
                                      V8HostRun* run,
                                      RunTerminalArbiter* arbiter,
                                      bool terminal,
                                      int32_t event,
                                      V8HostStatus status) {
  SessionRef session(AcquireSession(id));
  if (!session)
    return V8HOST_E_INVALID_STATE;
  return session->PostRunEvent(run, arbiter, terminal, event, status);
}

V8HostStatus Dispatcher::PostRelay(uint64_t id,
                                   V8HostRun* run,
                                   int32_t kind,
                                   const void* data,
                                   size_t len) {
  SessionRef session(AcquireSession(id));
  if (!session)
    return V8HOST_E_INVALID_STATE;
  return session->PostRelay(run, kind, data, len);
}

V8HostStatus Dispatcher::PostDisconnect(uint64_t id) {
  SessionRef session(AcquireSession(id));
  if (!session)
    return V8HOST_E_INVALID_STATE;
  return session->PostDisconnect();
}

V8HostStatus Dispatcher::SetCallbacks(uint64_t id,
                                      const V8HostCallbacks* callbacks) {
  SessionRef session(AcquireSession(id));
  if (!session)
    return V8HOST_E_INVALID_STATE;
  return session->SetCallbacks(callbacks);
}

// ---------------------------------------------------------------------------
// SessionDispatch
// ---------------------------------------------------------------------------

SessionDispatch* SessionDispatch::Create(Dispatcher* dispatcher,
                                         V8HostSession* handle,
                                         int32_t failed_state) {
  if (dispatcher == nullptr || !dispatcher->IsInitialized())
    return nullptr;
  const uint64_t id = dispatcher->AllocateSessionId();
  auto* session =
      new (std::nothrow) SessionDispatch(dispatcher, id, handle, failed_state);
  if (session == nullptr)
    return nullptr;
  // Register under sessions_mutex_ so the id-keyed producer API can resolve this
  // session. The creator reference (refcount 1) is returned to and owned by the
  // caller; CloseAndRelease unregisters before dropping it.
  dispatcher->RegisterSession(id, session);
  return session;
}

SessionDispatch::SessionDispatch(Dispatcher* dispatcher,
                                 uint64_t id,
                                 V8HostSession* handle,
                                 int32_t failed_state)
    : dispatcher_(dispatcher),
      id_(id),
      handle_(handle),
      failed_state_(failed_state) {
  LiveCounter().fetch_add(1, std::memory_order_relaxed);
}

SessionDispatch::~SessionDispatch() {
  LiveCounter().fetch_sub(1, std::memory_order_relaxed);
}

int SessionDispatch::live_count() {
  return LiveCounter().load(std::memory_order_relaxed);
}

void SessionDispatch::AddRef() {
  refcount_.fetch_add(1, std::memory_order_relaxed);
}

void SessionDispatch::Release() {
  if (refcount_.fetch_sub(1, std::memory_order_acq_rel) == 1)
    delete this;
}

V8HostStatus SessionDispatch::SetCallbacks(const V8HostCallbacks* callbacks) {
  if (callbacks == nullptr)
    return V8HOST_E_INVALID_ARG;
  // For version 1 every member is required, so the required size equals the
  // struct size. A larger struct_size (a future version) is accepted and only
  // the known fields are read.
  if (callbacks->struct_size < sizeof(V8HostCallbacks))
    return V8HOST_E_STRUCT_SIZE;

  V8HostCallbacks copy = {};
  copy.struct_size = sizeof(V8HostCallbacks);
  copy.context = callbacks->context;
  copy.on_session_state = callbacks->on_session_state;
  copy.on_run_event = callbacks->on_run_event;
  copy.on_relay_message = callbacks->on_relay_message;
  copy.on_broker_disconnect = callbacks->on_broker_disconnect;

  std::lock_guard<std::mutex> lock(mutex_);
  if (closed_)
    return V8HOST_E_INVALID_STATE;
  current_table_ = copy;
  return V8HOST_OK;
}

V8HostStatus SessionDispatch::PostSessionState(int32_t state,
                                               V8HostStatus status) {
  Event event;
  event.kind = EventKind::kSessionState;
  event.code = state;
  event.status = status;
  return Enqueue(std::move(event), /*terminal_run=*/false, /*arbiter=*/nullptr);
}

V8HostStatus SessionDispatch::PostRunEvent(V8HostRun* run,
                                           RunTerminalArbiter* arbiter,
                                           bool terminal,
                                           int32_t event,
                                           V8HostStatus status) {
  Event entry;
  entry.kind = EventKind::kRunEvent;
  entry.run = run;
  entry.code = event;
  entry.status = status;
  return Enqueue(std::move(entry), terminal, arbiter);
}

V8HostStatus SessionDispatch::PostRelay(V8HostRun* run,
                                        int32_t kind,
                                        const void* data,
                                        size_t len) {
  if (len > 0 && data == nullptr)
    return V8HOST_E_INVALID_ARG;
  Event event;
  event.kind = EventKind::kRelay;
  event.run = run;
  event.code = kind;
  if (len > 0) {
    // Copy the borrowed payload so it outlives the producer's buffer; it is
    // owned until the callback delivers and the event is destroyed.
    event.data.resize(len);
    std::memcpy(event.data.data(), data, len);
  }
  return Enqueue(std::move(event), /*terminal_run=*/false, /*arbiter=*/nullptr);
}

V8HostStatus SessionDispatch::PostDisconnect() {
  Event event;
  event.kind = EventKind::kDisconnect;
  return Enqueue(std::move(event), /*terminal_run=*/false, /*arbiter=*/nullptr);
}

V8HostStatus SessionDispatch::Enqueue(Event&& event,
                                      bool terminal_run,
                                      RunTerminalArbiter* arbiter) {
  V8HostStatus result = V8HOST_OK;
  bool need_post = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_)
      return V8HOST_E_INVALID_STATE;
    if (backpressure_failed_)
      return V8HOST_E_CALLBACK_BACKPRESSURE;

    if (queue_.size() >= kSessionQueueCapacity) {
      // The app thread is not draining. Fail the session: drop everything
      // pending and deliver exactly one terminal backpressure notification.
      // Backpressure SUPERSEDES run-terminal arbitration: a terminal
      // PostRunEvent that overflows returns V8HOST_E_CALLBACK_BACKPRESSURE and
      // does NOT claim the run arbiter (the arbiter check below is skipped on
      // this path) -- the session failure subsumes the run's terminal, and
      // backpressure_failed_ is sticky so no second terminal is ever delivered.
      backpressure_failed_ = true;
      queue_.clear();
      Event terminal;
      terminal.kind = EventKind::kSessionState;
      terminal.table = current_table_;
      terminal.code = failed_state_;
      terminal.status = V8HOST_E_CALLBACK_BACKPRESSURE;
      queue_.push_back(std::move(terminal));
      result = V8HOST_E_CALLBACK_BACKPRESSURE;
    } else {
      // Claim run-terminal arbitration only when the event is actually
      // enqueued, so a lost arbitration leaves the queue untouched.
      if (terminal_run && arbiter != nullptr && !arbiter->TryClaimTerminal())
        return V8HOST_E_RUN_TERMINAL;
      event.table = current_table_;  // snapshot at post time
      queue_.push_back(std::move(event));
      result = V8HOST_OK;
    }
    need_post = EnsureScheduledLocked();
  }

  // PostMessage is outside the lock but after AddRef (in EnsureScheduledLocked),
  // which is safe: no drain for this session can start before its message
  // exists. On failure revert and fail closed.
  if (need_post && !dispatcher_->PostDrain(this)) {
    OnPostFailed();
    return V8HOST_E_INTERNAL;
  }
  return result;
}

bool SessionDispatch::EnsureScheduledLocked() {
  if (scheduled_)
    return false;
  scheduled_ = true;
  AddRef();  // balanced by DrainFromMessage's Release (or OnPostFailed)
  return true;
}

void SessionDispatch::OnPostFailed() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    scheduled_ = false;
    backpressure_failed_ = true;
    queue_.clear();
  }
  Release();  // balance the AddRef taken in EnsureScheduledLocked
}

void SessionDispatch::DrainFromMessage(SessionDispatch* session) {
  session->DrainLoop();
  // Consumes the reference held by the posted message; may delete `session`.
  // Touch nothing on `session` after this.
  session->Release();
}

void SessionDispatch::DrainLoop() {
  for (;;) {
    Event event;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      // closed_ suppresses any remaining events (close cleared them already);
      // an empty queue ends the batch. Clearing scheduled_ under the lock lets
      // a future post schedule a fresh drain.
      if (closed_ || queue_.empty()) {
        scheduled_ = false;
        return;
      }
      event = std::move(queue_.front());
      queue_.pop_front();
    }
    // No lock held: the callback may reenter (post/set_callbacks/close).
    Invoke(event);
  }
}

void SessionDispatch::Invoke(const Event& event) {
  switch (event.kind) {
    case EventKind::kSessionState:
      if (event.table.on_session_state) {
        event.table.on_session_state(event.table.context, handle_, event.code,
                                     event.status);
      }
      break;
    case EventKind::kRunEvent:
      if (event.table.on_run_event) {
        event.table.on_run_event(event.table.context, event.run, event.code,
                                 event.status);
      }
      break;
    case EventKind::kRelay:
      if (event.table.on_relay_message) {
        event.table.on_relay_message(
            event.table.context, event.run, event.code,
            event.data.empty() ? nullptr : event.data.data(),
            event.data.size());
      }
      break;
    case EventKind::kDisconnect:
      if (event.table.on_broker_disconnect)
        event.table.on_broker_disconnect(event.table.context);
      break;
  }
}

void SessionDispatch::CloseAndRelease() {
  // Unregister FIRST, under sessions_mutex_, so no new producer can resolve this
  // id to us; a producer that already AddRef'd under that lock keeps us alive for
  // its in-flight post. Only then mark closed + suppress pending (session mutex_)
  // and drop the creator reference. sessions_mutex_ is not held across mutex_, so
  // there is no lock-order inversion with the id-keyed producer path.
  dispatcher_->UnregisterSession(id_);
  {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    queue_.clear();  // suppress pending, not-yet-delivered callbacks
  }
  // Drop the creator's reference. If a drain is in progress it holds its own
  // reference, so destruction is deferred until that callback unwinds.
  Release();
}

bool SessionDispatch::closed() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return closed_;
}

}  // namespace v8host::client
