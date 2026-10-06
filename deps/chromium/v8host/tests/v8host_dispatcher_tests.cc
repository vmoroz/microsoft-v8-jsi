// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Deterministic, in-process unit tests for the app-thread callback dispatcher
// (v8host_dispatcher). The test process IS the app/callback thread: it
// initializes the dispatcher on its main thread, drives producers from worker
// std::threads, pumps the message loop with a bounded deadline, and asserts the
// design section 9.1/9.3 properties. Threading is made deterministic with
// thread joins and callback-driven predicates (counts/flags), never with sleeps
// used as synchronization; the only time bounds are failure deadlines.

#include "v8host_test_support.h"  // brings in <windows.h>; must precede the header
#include "v8host_dispatcher.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using v8host::client::Dispatcher;
using v8host::client::RunTerminalArbiter;
using v8host::client::SessionDispatch;
using v8host::client::kSessionQueueCapacity;
using v8host::test::TestCase;

// The process-global app-thread dispatcher, initialized on main in main().
Dispatcher& G() { return Dispatcher::Instance(); }

bool Fail(std::string* detail, const char* message) {
  if (detail)
    *detail = message;
  return false;
}

// Opaque cookies echoed back to callbacks. Never dereferenced by the dispatcher;
// they stand in for the real V8HostSession*/V8HostRun* a client would pass.
V8HostSession* FakeSession(uintptr_t n) {
  return reinterpret_cast<V8HostSession*>(0x5E550000u + n);
}
V8HostRun* FakeRun(uintptr_t n) {
  return reinterpret_cast<V8HostRun*>(0x4A040000u + n);
}

// Pumps the app-thread message loop until `done()` holds or the deadline
// expires. Returns the final value of done(). Waiting for the next message uses
// a bounded wait that wakes on message arrival (not a sync sleep); correctness
// depends only on `done()`, with the timeout acting purely as a failure bound.
bool PumpUntil(const std::function<bool()>& done, DWORD timeout_ms = 5000) {
  const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
  while (!done()) {
    if (::GetTickCount64() >= deadline)
      return done();
    MSG msg;
    if (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      ::DispatchMessageW(&msg);
    } else {
      ::MsgWaitForMultipleObjectsEx(0, nullptr, 20, QS_ALLINPUT,
                                    MWMO_INPUTAVAILABLE);
    }
  }
  return true;
}

// Drains any remaining posted messages. Safe to call only once every session in
// the test has been closed, so a stray drain merely releases its reference and
// delivers nothing into out-of-scope state.
void DrainRemaining() {
  MSG msg;
  int guard = 0;
  while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE) && guard++ < 1000000)
    ::DispatchMessageW(&msg);
}

// Minimal manual-reset event for cross-thread test coordination (no pumping).
class ManualEvent {
 public:
  void Signal() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      set_ = true;
    }
    cv_.notify_all();
  }
  void Wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return set_; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  bool set_ = false;
};

// Records callback deliveries. All writes happen on the app thread (callbacks
// run only in the drain loop); the test reads after joining producers and
// pumping, also on the app thread, so no lock is needed. `total` is atomic only
// because the pump predicate reads it.
struct Recorder {
  std::vector<int32_t> session_states;
  std::vector<V8HostStatus> session_status;
  std::vector<int32_t> run_events;
  std::vector<int32_t> relay_kinds;
  std::vector<std::string> relay_data;
  int disconnects = 0;
  uint32_t last_thread_id = 0;
  V8HostSession* last_session = nullptr;
  V8HostRun* last_run = nullptr;
  std::atomic<int> total{0};
};

void V8HOST_CALL OnSessionState(void* context,
                                V8HostSession* session,
                                int32_t state,
                                V8HostStatus status) {
  auto* r = static_cast<Recorder*>(context);
  r->last_thread_id = ::GetCurrentThreadId();
  r->last_session = session;
  r->session_states.push_back(state);
  r->session_status.push_back(status);
  r->total.fetch_add(1, std::memory_order_relaxed);
}

void V8HOST_CALL OnRunEvent(void* context,
                            V8HostRun* run,
                            int32_t event,
                            V8HostStatus status) {
  auto* r = static_cast<Recorder*>(context);
  r->last_thread_id = ::GetCurrentThreadId();
  r->last_run = run;
  r->run_events.push_back(event);
  (void)status;
  r->total.fetch_add(1, std::memory_order_relaxed);
}

void V8HOST_CALL OnRelay(void* context,
                         V8HostRun* run,
                         int32_t kind,
                         const void* data,
                         size_t len) {
  auto* r = static_cast<Recorder*>(context);
  r->last_thread_id = ::GetCurrentThreadId();
  r->last_run = run;
  r->relay_kinds.push_back(kind);
  // A zero-length relay carries a null pointer; build an empty string rather
  // than std::string(nullptr, 0) (constructing from a null pointer is UB).
  if (len == 0 || data == nullptr)
    r->relay_data.emplace_back();
  else
    r->relay_data.emplace_back(static_cast<const char*>(data), len);
  r->total.fetch_add(1, std::memory_order_relaxed);
}

void V8HOST_CALL OnDisconnect(void* context) {
  auto* r = static_cast<Recorder*>(context);
  r->last_thread_id = ::GetCurrentThreadId();
  r->disconnects++;
  r->total.fetch_add(1, std::memory_order_relaxed);
}

V8HostCallbacks MakeTable(Recorder* r) {
  V8HostCallbacks t = {};
  t.struct_size = sizeof(V8HostCallbacks);
  t.context = r;
  t.on_session_state = &OnSessionState;
  t.on_run_event = &OnRunEvent;
  t.on_relay_message = &OnRelay;
  t.on_broker_disconnect = &OnDisconnect;
  return t;
}

// ---------------------------------------------------------------------------
// App-thread delivery, ordering, and every callback kind.
// ---------------------------------------------------------------------------

// Events posted from a worker thread are delivered on the captured app thread,
// in FIFO order per session.
bool AppThreadDeliveryAndOrdering(std::string* detail) {
  Recorder rec;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(1), 42);
  if (!sd)
    return Fail(detail, "create failed");
  const uint64_t id = sd->id();
  V8HostCallbacks table = MakeTable(&rec);
  G().SetCallbacks(id, &table);

  constexpr int kCount = 64;
  std::thread worker([&] {
    for (int i = 0; i < kCount; ++i)
      G().PostSessionState(id, 1000 + i, V8HOST_OK);
  });
  worker.join();  // all posts enqueued before we pump: deterministic

  PumpUntil([&] { return rec.total.load() >= kCount; });

  bool ok = true;
  if (static_cast<int>(rec.session_states.size()) != kCount) {
    ok = Fail(detail, "wrong delivered count");
  } else {
    for (int i = 0; i < kCount; ++i) {
      if (rec.session_states[i] != 1000 + i) {
        ok = Fail(detail, "FIFO order violated");
        break;
      }
    }
  }
  if (ok && rec.last_thread_id != G().callback_thread_id())
    ok = Fail(detail, "not delivered on the app thread");
  if (ok && rec.last_session != FakeSession(1))
    ok = Fail(detail, "session handle not echoed");

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// All four callback kinds are delivered on the app thread, in order, with the
// relay payload copied at post time (mutating the source afterward does not
// change what is delivered).
bool AllCallbackKinds(std::string* detail) {
  Recorder rec;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(13), 42);
  const uint64_t id = sd->id();
  V8HostCallbacks table = MakeTable(&rec);
  G().SetCallbacks(id, &table);

  V8HostRun* run = FakeRun(2);
  RunTerminalArbiter arbiter;
  char payload[12];
  std::memcpy(payload, "relay-bytes", 11);

  std::thread worker([&] {
    G().PostSessionState(id, 5, V8HOST_OK);
    G().PostRunEvent(id, run, nullptr, /*terminal=*/false, 6, V8HOST_OK);
    G().PostRelay(id, run, 9, payload, 11);
    G().PostRunEvent(id, run, &arbiter, /*terminal=*/true, 7, V8HOST_OK);
    G().PostDisconnect(id);
  });
  worker.join();
  std::memcpy(payload, "XXXXXXXXXXX", 11);  // mutate source after the copy

  PumpUntil([&] { return rec.total.load() >= 5; });

  bool ok = true;
  if (rec.last_thread_id != G().callback_thread_id())
    ok = Fail(detail, "not delivered on the app thread");
  else if (rec.session_states.size() != 1 || rec.session_states[0] != 5)
    ok = Fail(detail, "session event");
  else if (rec.run_events.size() != 2 || rec.run_events[0] != 6 ||
           rec.run_events[1] != 7)
    ok = Fail(detail, "run events / ordering");
  else if (rec.relay_kinds.size() != 1 || rec.relay_kinds[0] != 9 ||
           rec.relay_data[0] != "relay-bytes")
    ok = Fail(detail, "relay payload not copied at post time");
  else if (rec.disconnects != 1)
    ok = Fail(detail, "disconnect");
  else if (rec.last_run != run)
    ok = Fail(detail, "run handle not echoed");

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// ---------------------------------------------------------------------------
// Initialization: idempotent, thread-safe, no deadlock.
// ---------------------------------------------------------------------------

// A later initialize (on the app thread or a worker) succeeds and does not
// change the captured callback thread.
bool IdempotentInit(std::string* detail) {
  const uint32_t app = G().callback_thread_id();
  if (app != ::GetCurrentThreadId())
    return Fail(detail, "app thread is not the test main thread");
  if (G().Initialize() != V8HOST_OK)
    return Fail(detail, "reinitialize on app thread failed");
  if (G().callback_thread_id() != app)
    return Fail(detail, "callback thread changed on reinitialize");

  std::atomic<V8HostStatus> worker_status{V8HOST_E_INTERNAL};
  std::thread worker([&] { worker_status = G().Initialize(); });
  worker.join();
  if (worker_status.load() != V8HOST_OK)
    return Fail(detail, "initialize from worker failed");
  if (G().callback_thread_id() != app)
    return Fail(detail, "callback thread changed from worker initialize");
  return true;
}

// Many threads initialize a fresh dispatcher at once: exactly one captures the
// callback thread and creates the window, the rest wait (on a condition
// variable, never pumping) and return OK, and nothing deadlocks.
bool ConcurrentInitNoDeadlock(std::string* detail) {
  Dispatcher d;
  constexpr int kThreads = 4;
  std::atomic<int> arrived{0};
  std::atomic<int> finished{0};
  std::atomic<int> ok_count{0};
  std::atomic<int> winner_count{0};
  std::atomic<uint32_t> winner_tid{0};
  ManualEvent go;
  ManualEvent teardown;

  std::vector<std::thread> threads;
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&] {
      arrived.fetch_add(1);
      go.Wait();  // release all racers together
      const V8HostStatus status = d.Initialize();
      if (status == V8HOST_OK)
        ok_count.fetch_add(1);
      const bool winner = d.callback_thread_id() == ::GetCurrentThreadId();
      if (winner) {
        winner_tid.store(::GetCurrentThreadId());
        winner_count.fetch_add(1);
      }
      finished.fetch_add(1);
      if (winner) {
        teardown.Wait();        // keep the owner alive to hold its window
        d.ShutdownForTesting();  // destroy the window on its creating thread
      }
    });
  }

  while (arrived.load() < kThreads)
    std::this_thread::yield();
  go.Signal();

  const ULONGLONG deadline = ::GetTickCount64() + 5000;
  while (finished.load() < kThreads && ::GetTickCount64() < deadline)
    std::this_thread::yield();

  bool ok = true;
  if (finished.load() != kThreads)
    ok = Fail(detail, "initialize did not complete (possible deadlock)");
  else if (ok_count.load() != kThreads)
    ok = Fail(detail, "not every initialize returned OK");
  else if (winner_count.load() != 1)
    ok = Fail(detail, "not exactly one thread captured the callback thread");
  else if (!d.IsInitialized())
    ok = Fail(detail, "dispatcher not initialized");
  else if (d.callback_thread_id() != winner_tid.load())
    ok = Fail(detail, "callback thread id mismatch");

  teardown.Signal();
  for (std::thread& th : threads)
    th.join();
  return ok;
}

// ---------------------------------------------------------------------------
// Callback-table snapshots: replace and clear.
// ---------------------------------------------------------------------------

// An event queued under table A is delivered to A even though set_callbacks
// swapped to B before it was pumped; a later event uses B; a cleared table
// (NULL members) declines cleanly without affecting FIFO order.
bool TableSnapshotAndReplace(std::string* detail) {
  Recorder rec_a;
  Recorder rec_b;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(4), 42);
  const uint64_t id = sd->id();

  V8HostCallbacks table_a = MakeTable(&rec_a);
  G().SetCallbacks(id, &table_a);
  G().PostSessionState(id, 111, V8HOST_OK);  // snapshot A (not yet pumped)

  V8HostCallbacks table_b = MakeTable(&rec_b);
  G().SetCallbacks(id, &table_b);
  G().PostSessionState(id, 222, V8HOST_OK);  // snapshot B

  PumpUntil([&] { return rec_a.total.load() >= 1 && rec_b.total.load() >= 1; });

  bool ok = true;
  if (rec_a.session_states.size() != 1 || rec_a.session_states[0] != 111)
    ok = Fail(detail, "in-flight event did not keep its table A snapshot");
  else if (rec_b.session_states.size() != 1 || rec_b.session_states[0] != 222)
    ok = Fail(detail, "later event did not use replacement table B");

  if (ok) {
    // Clear with a valid table whose members are all NULL: declines cleanly.
    V8HostCallbacks cleared = {};
    cleared.struct_size = sizeof(V8HostCallbacks);
    G().SetCallbacks(id, &cleared);
    G().PostSessionState(id, 333, V8HOST_OK);  // should be dropped on delivery

    // Reinstall A and post a sentinel; FIFO guarantees 333 is processed before
    // the sentinel, so if 333 were delivered it would appear somewhere.
    G().SetCallbacks(id, &table_a);
    G().PostSessionState(id, 999, V8HOST_OK);
    PumpUntil([&] { return rec_a.total.load() >= 2; });

    if (rec_a.session_states.size() != 2 || rec_a.session_states[1] != 999)
      ok = Fail(detail, "sentinel after clear not delivered to A");
    else if (rec_b.total.load() != 1)
      ok = Fail(detail, "cleared/declined event leaked to a callback");
  }

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// ---------------------------------------------------------------------------
// Backpressure: a stalled app thread fails the session once, drops the rest,
// and never blocks the producer.
// ---------------------------------------------------------------------------
bool Backpressure(std::string* detail) {
  Recorder rec;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(5), 77);
  const uint64_t id = sd->id();
  V8HostCallbacks table = MakeTable(&rec);
  G().SetCallbacks(id, &table);

  const int cap = static_cast<int>(kSessionQueueCapacity);
  std::atomic<int> accepted{0};
  std::atomic<int> backpressured{0};
  std::atomic<int> other{0};

  // The app thread does not pump while the worker overfills (it is parked in
  // join()), so nothing drains and the queue fills. The worker never blocks.
  std::thread worker([&] {
    for (int i = 0; i < cap + 5; ++i) {
      const V8HostStatus s = G().PostSessionState(id, 2000 + i, V8HOST_OK);
      if (s == V8HOST_OK)
        accepted.fetch_add(1);
      else if (s == V8HOST_E_CALLBACK_BACKPRESSURE)
        backpressured.fetch_add(1);
      else
        other.fetch_add(1);
    }
  });
  worker.join();

  bool ok = true;
  if (accepted.load() != cap)
    ok = Fail(detail, "accepted count != capacity");
  else if (backpressured.load() != 5)
    ok = Fail(detail, "backpressure return count");
  else if (other.load() != 0)
    ok = Fail(detail, "unexpected post status");

  if (ok) {
    PumpUntil([&] { return rec.total.load() >= 1; });
    // Exactly one terminal was ever enqueued for delivery (the queue was
    // cleared on overflow), so when total reaches 1 it stays 1.
    if (rec.total.load() != 1)
      ok = Fail(detail, "expected exactly one delivered callback");
    else if (rec.session_states[0] != 77 ||
             rec.session_status[0] != V8HOST_E_CALLBACK_BACKPRESSURE)
      ok = Fail(detail, "terminal is not the backpressure failure");
    else if (rec.last_session != FakeSession(5))
      ok = Fail(detail, "terminal session handle not echoed");
  }

  if (ok) {
    // Post-after-terminal: the session stays failed, so a further post is
    // rejected with BACKPRESSURE and delivers nothing (no second terminal).
    const V8HostStatus after = G().PostSessionState(id, 2999, V8HOST_OK);
    if (after != V8HOST_E_CALLBACK_BACKPRESSURE)
      ok = Fail(detail, "post after terminal not rejected with backpressure");
    else {
      DrainRemaining();
      if (rec.total.load() != 1)
        ok = Fail(detail, "post after terminal delivered an extra callback");
    }
  }

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// ---------------------------------------------------------------------------
// Reentrancy: a callback that posts, replaces the table, or closes.
// ---------------------------------------------------------------------------
struct ReentryCtx {
  SessionDispatch* sd = nullptr;
  uint64_t id = 0;
  int mode = 0;  // 0 = post, 1 = set_callbacks, 2 = close
  int reenter_budget = 0;
  bool swapped = false;
  bool closed_once = false;
  bool alive_after_close = false;
  const V8HostCallbacks* table_b = nullptr;
  uint32_t tid = 0;
  std::atomic<int> total{0};
};

void V8HOST_CALL ReentrySessionCb(void* context,
                                  V8HostSession* /*session*/,
                                  int32_t /*state*/,
                                  V8HostStatus /*status*/) {
  auto* x = static_cast<ReentryCtx*>(context);
  x->tid = ::GetCurrentThreadId();
  x->total.fetch_add(1, std::memory_order_relaxed);

  if (x->mode == 0 && x->reenter_budget > 0) {
    --x->reenter_budget;
    G().PostSessionState(x->id, 9000 + x->reenter_budget, V8HOST_OK);
  } else if (x->mode == 1 && !x->swapped) {
    x->swapped = true;
    G().SetCallbacks(x->id, x->table_b);          // swap table for future posts
    G().PostSessionState(x->id, 777, V8HOST_OK);  // captured under table B
  } else if (x->mode == 2 && !x->closed_once) {
    x->closed_once = true;
    x->sd->CloseAndRelease();                     // close from inside a callback
    // The drain still holds a reference, so the object is alive here: this read
    // is the deferred-destruction guarantee (a freed object would be a UAF).
    x->alive_after_close = x->sd->closed();
  }
}

V8HostCallbacks MakeReentryTable(ReentryCtx* ctx) {
  V8HostCallbacks t = {};
  t.struct_size = sizeof(V8HostCallbacks);
  t.context = ctx;
  t.on_session_state = &ReentrySessionCb;
  return t;
}

// A callback that posts a follow-up event: all re-posted events are delivered
// by the same drain loop on the app thread, with no deadlock.
bool ReentrantPost(std::string* detail) {
  ReentryCtx ctx;
  ctx.mode = 0;
  ctx.reenter_budget = 3;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(6), 42);
  ctx.sd = sd;
  ctx.id = sd->id();
  V8HostCallbacks table = MakeReentryTable(&ctx);
  G().SetCallbacks(ctx.id, &table);

  G().PostSessionState(ctx.id, 1, V8HOST_OK);
  PumpUntil([&] { return ctx.total.load() >= 4; });

  bool ok = true;
  if (ctx.total.load() != 4)
    ok = Fail(detail, "reentrant posts not all delivered");
  else if (ctx.tid != G().callback_thread_id())
    ok = Fail(detail, "reentrant delivery off the app thread");

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// A callback that replaces the table: the event it posts afterward is delivered
// under the new table.
bool ReentrantSetCallbacks(std::string* detail) {
  Recorder rec_b;
  ReentryCtx ctx;
  ctx.mode = 1;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(9), 42);
  ctx.sd = sd;
  ctx.id = sd->id();
  V8HostCallbacks table_b = MakeTable(&rec_b);
  ctx.table_b = &table_b;
  V8HostCallbacks table_a = MakeReentryTable(&ctx);
  G().SetCallbacks(ctx.id, &table_a);

  G().PostSessionState(ctx.id, 1, V8HOST_OK);  // under A -> swaps to B, posts 777
  PumpUntil([&] { return ctx.total.load() >= 1 && rec_b.total.load() >= 1; });

  bool ok = true;
  if (ctx.total.load() != 1)
    ok = Fail(detail, "table A over-delivered");
  else if (rec_b.session_states.size() != 1 || rec_b.session_states[0] != 777)
    ok = Fail(detail, "reentrant set_callbacks not honored for next event");

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// A callback that closes its own session: the remaining queued events are
// suppressed, destruction is deferred until the drain unwinds, and there is no
// use-after-free.
bool ReentrantClose(std::string* detail) {
  const int base = SessionDispatch::live_count();
  ReentryCtx ctx;
  ctx.mode = 2;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(7), 42);
  ctx.sd = sd;
  ctx.id = sd->id();
  V8HostCallbacks table = MakeReentryTable(&ctx);
  G().SetCallbacks(ctx.id, &table);

  for (int i = 0; i < 5; ++i)
    G().PostSessionState(ctx.id, 500 + i, V8HOST_OK);

  // The first delivery closes the session; the remaining four are suppressed.
  PumpUntil([&] { return ctx.total.load() >= 1; });
  DrainRemaining();

  bool ok = true;
  if (ctx.total.load() != 1)
    ok = Fail(detail, "close-from-callback did not suppress remaining events");
  else if (!ctx.alive_after_close)
    ok = Fail(detail, "object destroyed under the callback (no deferred delete)");
  else if (SessionDispatch::live_count() != base)
    ok = Fail(detail, "session not destroyed after the drain unwound");
  // sd is destroyed; do not touch it.
  return ok;
}

// ---------------------------------------------------------------------------
// One terminal per run.
// ---------------------------------------------------------------------------

// Many threads attempt the terminal run event for one run; exactly one wins the
// arbiter and exactly one terminal is delivered.
bool OneTerminalPerRun(std::string* detail) {
  Recorder rec;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(10), 42);
  const uint64_t id = sd->id();
  V8HostCallbacks table = MakeTable(&rec);
  G().SetCallbacks(id, &table);

  RunTerminalArbiter arbiter;
  V8HostRun* run = FakeRun(1);
  constexpr int kThreads = 8;
  std::atomic<int> accepted{0};
  std::atomic<int> rejected{0};

  std::vector<std::thread> threads;
  for (int i = 0; i < kThreads; ++i) {
    threads.emplace_back([&, i] {
      const V8HostStatus s = G().PostRunEvent(id, run, &arbiter,
                                              /*terminal=*/true, 7000 + i,
                                              V8HOST_OK);
      if (s == V8HOST_OK)
        accepted.fetch_add(1);
      else if (s == V8HOST_E_RUN_TERMINAL)
        rejected.fetch_add(1);
    });
  }
  for (std::thread& th : threads)
    th.join();

  PumpUntil([&] { return rec.total.load() >= 1; });

  bool ok = true;
  if (accepted.load() != 1)
    ok = Fail(detail, "more than one terminal accepted");
  else if (rejected.load() != kThreads - 1)
    ok = Fail(detail, "losing terminals not rejected with RUN_TERMINAL");
  else if (rec.run_events.size() != 1)
    ok = Fail(detail, "more than one terminal delivered");

  sd->CloseAndRelease();
  DrainRemaining();
  return ok;
}

// ---------------------------------------------------------------------------
// Close: suppression, non-blocking, deferred destruction under stress.
// ---------------------------------------------------------------------------

// close suppresses queued-but-undelivered callbacks and returns without
// blocking; the session is destroyed once its pending drain is pumped out.
bool CloseSuppression(std::string* detail) {
  const int base = SessionDispatch::live_count();
  Recorder rec;
  SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(11), 42);
  const uint64_t id = sd->id();
  V8HostCallbacks table = MakeTable(&rec);
  G().SetCallbacks(id, &table);

  for (int i = 0; i < 20; ++i)
    G().PostSessionState(id, i, V8HOST_OK);  // queued, not pumped
  sd->CloseAndRelease();                     // non-blocking; suppresses the queue

  DrainRemaining();  // stray drain sees closed_, releases, delivers nothing

  bool ok = true;
  if (rec.total.load() != 0)
    ok = Fail(detail, "close did not suppress queued callbacks");
  else if (SessionDispatch::live_count() != base)
    ok = Fail(detail, "session not destroyed after drain");
  return ok;
}

// Stress the close-from-callback / deferred-destruction path across many
// iterations with producers on a worker thread: no leak, no use-after-free.
bool CloseFromCallbackStress(std::string* detail) {
  const int base = SessionDispatch::live_count();
  for (int iter = 0; iter < 300; ++iter) {
    ReentryCtx ctx;
    ctx.mode = 2;
    SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(12), 42);
    ctx.sd = sd;
    ctx.id = sd->id();
    V8HostCallbacks table = MakeReentryTable(&ctx);
    G().SetCallbacks(ctx.id, &table);

    std::thread worker([&] {
      for (int i = 0; i < 10; ++i)
        G().PostSessionState(ctx.id, i, V8HOST_OK);
    });
    worker.join();

    PumpUntil([&] { return ctx.total.load() >= 1; });
    DrainRemaining();

    if (!ctx.alive_after_close)
      return Fail(detail, "object freed under the callback (use-after-free)");
    if (ctx.total.load() != 1)
      return Fail(detail, "suppression failed under stress");
    if (SessionDispatch::live_count() != base)
      return Fail(detail, "leak or double-free under stress");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Concurrency: a producer posts by id while the owner closes (C1 regression).
// ---------------------------------------------------------------------------

// A producer tight-loops Dispatcher::PostRelay(id, ...) on one thread while the
// owner concurrently CloseAndRelease()es on another, for many bounded cycles.
// Routing posts through the never-freed Dispatcher by SESSION ID is what makes
// this memory-safe: the producer either resolves the id to a counted reference
// before the owner unregisters it (the post rides or is suppressed) or finds the
// id already gone and drops with V8HOST_E_INVALID_STATE -- it never dereferences
// a freed SessionDispatch. The pre-fix design posted to a raw `sd` pointer and
// was a heap-use-after-free on exactly this interleaving (finding C1), so this
// case FAILS under AddressSanitizer against the old code. Determinism: bounded
// cycles + a structural ready/close handoff (no sleeps); correctness depends only
// on the id-routing invariant, never on timing.
bool ConcurrentPostVsClose(std::string* detail) {
  const int base = SessionDispatch::live_count();
  constexpr int kCycles = 1000;
  for (int cycle = 0; cycle < kCycles; ++cycle) {
    SessionDispatch* sd = SessionDispatch::Create(&G(), FakeSession(20), 42);
    if (!sd)
      return Fail(detail, "create failed");
    const uint64_t id = sd->id();

    std::atomic<bool> producer_ready{false};
    std::atomic<bool> bad_status{false};
    std::thread producer([&] {
      producer_ready.store(true, std::memory_order_release);
      for (int i = 0; i < 64; ++i) {
        // Each post is accepted (session open), dropped with INVALID_STATE
        // (already closed), or -- defensively -- BACKPRESSURE; never a crash and
        // never any other status.
        const V8HostStatus s = G().PostRelay(id, FakeRun(1), i, nullptr, 0);
        if (s != V8HOST_OK && s != V8HOST_E_INVALID_STATE &&
            s != V8HOST_E_CALLBACK_BACKPRESSURE)
          bad_status.store(true, std::memory_order_relaxed);
      }
    });

    // Structural handoff: let the producer start before the owner closes, so the
    // close lands amid the producer's posts (the C1 interleaving) each cycle.
    while (!producer_ready.load(std::memory_order_acquire))
      std::this_thread::yield();
    sd->CloseAndRelease();  // owner drops the creator ref, racing the producer
    producer.join();

    if (bad_status.load(std::memory_order_relaxed))
      return Fail(detail, "producer saw an unexpected post status");
    // After close + join the id is unregistered: a further post is dropped with
    // INVALID_STATE, never a crash.
    if (G().PostRelay(id, FakeRun(1), 0, nullptr, 0) != V8HOST_E_INVALID_STATE)
      return Fail(detail, "post after close did not return INVALID_STATE");

    // Release any drain this cycle scheduled (it sees closed_ and just releases),
    // then confirm no leak / double-free: live_count returns to baseline.
    DrainRemaining();
    if (SessionDispatch::live_count() != base)
      return Fail(detail, "leak or double-free across a post-vs-close cycle");
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  // The test main thread IS the app/callback thread: initialize here so every
  // delivery test has a valid message-only window to pump.
  if (G().Initialize() != V8HOST_OK) {
    std::printf("fatal: dispatcher initialize failed\n");
    return 2;
  }

  const std::vector<TestCase> tests = {
      {"delivery", "app-thread-ordering", AppThreadDeliveryAndOrdering},
      {"delivery", "all-callback-kinds", AllCallbackKinds},
      {"init", "idempotent", IdempotentInit},
      {"init", "concurrent-no-deadlock", ConcurrentInitNoDeadlock},
      {"snapshot", "replace-and-clear", TableSnapshotAndReplace},
      {"backpressure", "overflow-fails-once", Backpressure},
      {"reentrancy", "post", ReentrantPost},
      {"reentrancy", "set-callbacks", ReentrantSetCallbacks},
      {"reentrancy", "close", ReentrantClose},
      {"run", "one-terminal", OneTerminalPerRun},
      {"close", "suppression-nonblocking", CloseSuppression},
      {"close", "from-callback-stress", CloseFromCallbackStress},
      {"concurrency", "post-vs-close", ConcurrentPostVsClose},
  };

  // `--all` (or no filter) runs everything; RunTests also honors --suite/--case.
  return v8host::test::RunTests(argc, argv, tests);
}
