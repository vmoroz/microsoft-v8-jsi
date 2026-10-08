// v8host_engine.cc — the REAL V8/JSI engine persona of v8host.dll, driven by the
// product sbox.exe container over the sbox.h plugin ABI. It implements the
// configure/warmup/run/shutdown callbacks; v8host_plugin.cc composes them with
// the coordinator callback into the exported plugin vtable.
//
// Control inversion: the container (sbox.exe) owns main() and the sandbox
// lifecycle; this DLL links ONLY sbox.h (never the sandbox core) and reaches the
// message channel through the sbox_worker_api function pointers.
//
//   configure  BROKER        : decode the V8HostSpawnConfigV1 (session envelope +
//                              effective worker profile), drive every sbox config
//                              setter, and encode the V8HostWorkerProfileV1
//                              (engine DLL, jitless, optional snapshot) into
//                              opaque plugin_data.
//   warmup     PRE-lockdown  : decode plugin_data, load the engine DLL, set
//                              --jitless, (optional) startup snapshot, read the
//                              guest JS, create the JSI runtime, install `host`.
//                              All codegen/patching happens HERE — ACG forbids it
//                              afterward.
//   (sbox.exe lowers the token here: ACG armed)
//   run        POST-lockdown : evaluate the guest (interpreted under jitless, safe
//                              post-ACG), then own the JS thread in the message
//                              loop until the host closes the channel.
//   shutdown                 : tear down the runtime + engine handle.
//
// IMPORTANT: this drives v8jsi through the **JSI C++ API** (facebook::jsi via
// JsiAbiRuntime), NOT the raw ABI-safe C interface. The C ABI is the binary-
// stable boundary INSIDE the DLL; C++ consumers use jsi.h + JsiAbiRuntime.h
// (both shipped in the NuGet package). Only the config seam (the configure
// callback that wires the task runner) stays on the C ABI, because that IS the
// ABI boundary.

#include "sbox.h"
#include "v8host_engine.h"
#include "v8host_run_envelope.h"  // neutral per-run START/RELAY/CANCEL/RESULT codec
#include "v8host_spawn_apply.h"  // ApplySpawnConfig + the spawn/worker-profile codec

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <string>
#include <vector>

// Header-only loader hardening (ExeDir): resolves the engine DLL by full path
// from the app dir. Inline + kernel32-only here, so it pulls in NO sandbox core.
#include "sbox_harden.h"

// JSI C++ API (consumer-compiled, via jsi_cpp) + the v8jsi config header (its
// setters are resolved from the engine DLL by name and used inside the configure
// callback — the legitimate C ABI seam).
#include <jsi/jsi.h>

#include "jsi_abi/JsiAbiRuntime.h"
#include "jsi_abi/v8_jsi_config.h"

namespace {

using namespace facebook::jsi;  // Runtime, Value, Object, Function, String, ...

//==========================================================================
// Persona state — created in warmup (pre-lockdown), used in run
// (post-lockdown), torn down in shutdown. Kept in DLL file-scope statics
// because the container, not this DLL, owns main() and the call sequence.
//==========================================================================
sbox_worker g_worker = nullptr;          // the worker run context (opaque)
const sbox_worker_api* g_api = nullptr;  // worker services (message channel)

HMODULE g_engine = nullptr;                // the loaded engine DLL
Runtime* g_rt = nullptr;                   // owned; deleted in shutdown
std::string g_guest_src;                   // guest source, read pre-lockdown
bool g_use_guest_file = false;             // custom guest vs. built-in demo

// Diagnostics sink. As a sandbox payload this process has no console of its own,
// so plain stdout is often invisible. Mirror every diagnostic line to the
// debugger output as well, so a debugger / DebugView captures it regardless of
// how the process was launched. Used via the `printf` redefine below, so all
// existing call sites are covered.
inline void HostLog(const char* fmt, ...) {
  char buf[2048];
  va_list ap;
  va_start(ap, fmt);
  const int n = ::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0)
    return;
  ::fputs(buf, stdout);
  ::OutputDebugStringA(buf);
}
#define printf HostLog

// Resolve an engine-DLL export by name (decltype(&name) + GetProcAddress).
#define RESOLVE(mod, name)                                               \
  auto p_##name =                                                        \
      reinterpret_cast<decltype(&name)>(::GetProcAddress((mod), #name)); \
  if (!p_##name) {                                                       \
    printf("[v8host] missing v8jsi export: %s\n", #name);                \
    return sbox_error;                                                   \
  }

void PrintAcgStatus() {
  PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc = {};
  if (::GetProcessMitigationPolicy(::GetCurrentProcess(),
                                   ProcessDynamicCodePolicy, &dc, sizeof(dc))) {
    printf("[v8host] ACG (ProhibitDynamicCode) = %s\n",
           dc.ProhibitDynamicCode ? "ON" : "off");
  }
}

// Direct ACG probe: under MITIGATION_DYNAMIC_CODE_DISABLE a PAGE_EXECUTE_READWRITE
// allocation is refused with ERROR_DYNAMIC_CODE_BLOCKED (1655). Reads kernel
// state directly — the strongest post-lockdown proof that ACG is in force.
bool CanAllocExecutable(DWORD* last_error) {
  void* p = ::VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
  if (p) {
    ::VirtualFree(p, 0, MEM_RELEASE);
    if (last_error) *last_error = ERROR_SUCCESS;
    return true;
  }
  if (last_error) *last_error = ::GetLastError();
  return false;
}

// Read an entire file into a string of UTF-8 bytes. Returns false (leaving
// `out` unspecified) if the file can't be opened or fully read. Used to load a
// host-supplied guest script PRE-lockdown — after the token is lowered the
// payload can no longer open arbitrary files.
bool ReadFileBytes(const std::wstring& path, std::string& out) {
  HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE)
    return false;
  LARGE_INTEGER size = {};
  bool ok = ::GetFileSizeEx(h, &size) != 0;
  DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
  if (ok && (size.QuadPart < 0 ||
             static_cast<unsigned long long>(size.QuadPart) >
                 std::numeric_limits<size_t>::max())) {
    ok = false;
    error = ERROR_FILE_TOO_LARGE;
  }
  if (ok) {
    out.assign(static_cast<size_t>(size.QuadPart), '\0');
    size_t total = 0;
    while (total < out.size()) {
      DWORD want =
          static_cast<DWORD>(std::min<size_t>(out.size() - total, 1u << 28));
      DWORD got = 0;
      const BOOL read_ok = ::ReadFile(h, &out[total], want, &got, nullptr);
      if (!read_ok || got == 0) {
        error = read_ok ? ERROR_HANDLE_EOF : ::GetLastError();
        ok = false;
        break;
      }
      total += got;
    }
  }
  ::CloseHandle(h);
  if (!ok)
    ::SetLastError(error);
  return ok;
}

std::wstring EnvW(const wchar_t* name) {
  wchar_t buf[MAX_PATH] = {};
  DWORD n = ::GetEnvironmentVariableW(name, buf, MAX_PATH);
  return (n == 0 || n >= MAX_PATH) ? std::wstring() : std::wstring(buf, n);
}

// UTF-8 <-> UTF-16 bridges between the neutral spawn/worker-profile codec (UTF-8)
// and the Win32 wide APIs (engine DLL / snapshot paths). Lossless for valid
// Unicode (the codec guarantees strict UTF-8 / no NUL); empty maps to empty.
std::wstring Utf8ToWide(const std::string& utf8) {
  if (utf8.empty())
    return std::wstring();
  const int needed =
      ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                            static_cast<int>(utf8.size()), nullptr, 0);
  if (needed <= 0)
    return std::wstring();
  std::wstring wide(static_cast<size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                        static_cast<int>(utf8.size()), wide.data(), needed);
  return wide;
}
std::string WideToUtf8(const std::wstring& wide) {
  if (wide.empty())
    return std::string();
  const int needed =
      ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                            nullptr, 0, nullptr, nullptr);
  if (needed <= 0)
    return std::string();
  std::string utf8(static_cast<size_t>(needed), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        utf8.data(), needed, nullptr, nullptr);
  return utf8;
}

bool ReadGuestPath(std::wstring& path) {
  constexpr wchar_t name[] = L"V8HOST_GUEST_JS";
  ::SetLastError(ERROR_SUCCESS);
  const DWORD required = ::GetEnvironmentVariableW(name, nullptr, 0);
  if (!required) {
    const DWORD error = ::GetLastError();
    return error == ERROR_SUCCESS || error == ERROR_ENVVAR_NOT_FOUND;
  }
  path.resize(required);
  ::SetLastError(ERROR_SUCCESS);
  const DWORD length = ::GetEnvironmentVariableW(name, path.data(), required);
  if ((!length && ::GetLastError() != ERROR_SUCCESS) || length >= required) {
    if (length >= required)
      ::SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return false;
  }
  path.resize(length);
  return true;
}

//==========================================================================
// QPC timing split. Capture a timestamp at each startup boundary and print the
// delta as `[v8host][perf] <segment> = N.N ms`. These lines go through HostLog,
// so they reach BOTH stdout and OutputDebugString. Defaulting on; V8HOST_PERF=0
// silences. (The `lockdown` segment is not emitted here — LowerToken now runs in
// the container between warmup and run, not inside this DLL.)
//==========================================================================
struct Perf {
  LARGE_INTEGER freq{};
  bool on = true;
  void init() {
    ::QueryPerformanceFrequency(&freq);
    on = EnvW(L"V8HOST_PERF") != L"0";
  }
  LONGLONG now() const {
    LARGE_INTEGER t;
    ::QueryPerformanceCounter(&t);
    return t.QuadPart;
  }
  double ms(LONGLONG from, LONGLONG to) const {
    return freq.QuadPart ? static_cast<double>(to - from) * 1000.0 /
                               static_cast<double>(freq.QuadPart)
                         : 0.0;
  }
  void emit(const char* segment, LONGLONG from, LONGLONG to) const {
    if (on)
      printf("[v8host][perf] %-14s = %.1f ms\n", segment, ms(from, to));
  }
};

Perf g_perf;
LONGLONG g_first_post_qpc = 0;
inline void MarkFirstPost() {
  if (g_first_post_qpc == 0)
    g_first_post_qpc = g_perf.now();
}

//==========================================================================
// Foreground task runner (wired into the JSI config via the C ABI seam).
//
// V8 may post foreground tasks (from background workers, the inspector, etc.).
// We own the JS thread, so the task runner just enqueues onto a thread-safe
// queue and wakes the loop; the loop runs them on the JS thread.
//==========================================================================

struct CTask {
  void* data;
  v8_jsi_task_run_cb run;
  jsi_data_delete_cb del;
  void* deleter_data;
};

struct TaskQueue {
  CRITICAL_SECTION cs;
  std::vector<CTask> tasks;
  HANDLE wake = nullptr;  // auto-reset; signaled when a task is posted
};

// Heap-allocated in warmup, freed in shutdown; held as a pointer so there is no
// exit-time destructor racing the runtime teardown.
TaskQueue* g_tasks = nullptr;

// Called by the DLL (possibly on a background thread) to post a foreground task.
void JSI_CDECL PostTaskCb(void* runner_data, void* task_data,
                          v8_jsi_task_run_cb task_run_cb,
                          jsi_data_delete_cb task_data_delete_cb,
                          void* deleter_data) {
  auto* q = static_cast<TaskQueue*>(runner_data);
  ::EnterCriticalSection(&q->cs);
  q->tasks.push_back({task_data, task_run_cb, task_data_delete_cb, deleter_data});
  ::LeaveCriticalSection(&q->cs);
  ::SetEvent(q->wake);
}

// Called when the runtime is destroyed. runner_data points at g_tasks (process
// lifetime) so we don't free it — but fire the delete cb of any task still
// queued so nothing leaks.
void JSI_CDECL TaskRunnerDeleteCb(void* runner_data, void* /*deleter_data*/) {
  auto* q = static_cast<TaskQueue*>(runner_data);
  ::EnterCriticalSection(&q->cs);
  for (auto& t : q->tasks)
    if (t.del)
      t.del(t.data, t.deleter_data);
  q->tasks.clear();
  ::LeaveCriticalSection(&q->cs);
}

// Run (and free) all queued foreground tasks on the JS thread.
void RunQueuedTasks(TaskQueue* q) {
  std::vector<CTask> local;
  ::EnterCriticalSection(&q->cs);
  local.swap(q->tasks);
  ::LeaveCriticalSection(&q->cs);
  for (auto& t : local) {
    if (t.run)
      t.run(t.data);
    if (t.del)
      t.del(t.data, t.deleter_data);
  }
}

// Resolved v8jsi config setters (called inside the configure callback, which
// runs synchronously during v8_create_runtime). Set before create.
decltype(&v8_jsi_config_set_task_runner) g_set_task_runner = nullptr;
decltype(&v8_jsi_config_set_explicit_microtask_policy) g_set_microtask = nullptr;
decltype(&v8_jsi_config_set_startup_snapshot) g_set_snapshot = nullptr;

// Optional startup-snapshot blob (V8HOST_SNAPSHOT), read pre-lockdown. Held for
// the process lifetime so the bytes outlive the runtime; passed to the config
// with a NULL deleter (this DLL owns them, not the runtime).
std::string g_snapshot_blob;
bool g_have_snapshot = false;

// Whether ACG must be in force post-lockdown. Stashed in warmup from the bound
// worker profile's jitless tier: untrusted (jitless) => ACG enforced; trusted
// (JIT) => ACG off. The post-lockdown probe is gated by this so a trusted worker
// is not failed for (correctly) being allowed to allocate executable memory.
bool g_expect_acg = true;

// Per-run dispatch state (mutated only on the JS thread). A coordinator START
// envelope makes a run active; the dev-ambient path (the `sbox.exe --broker`
// smoke) keeps this 0 so guest output posts bare and inbound bare frames reach
// host.onmessage exactly as before. g_run_complete_requested is set by the
// neutral host.complete() and consumed by the run loop to emit a single
// RESULT(kCompleted).
uint32_t g_active_run_id = 0;
bool g_run_complete_requested = false;

jsi_error_code JSI_CDECL ConfigureRuntime(void* /*cb_data*/, jsi_config cfg) {
  if (g_set_task_runner)
    g_set_task_runner(cfg, g_tasks, &PostTaskCb, &TaskRunnerDeleteCb, nullptr);
  // Explicit microtask policy: promise jobs run only when we drain them on the
  // JS thread (after each loop turn), giving the host deterministic control.
  if (g_set_microtask)
    g_set_microtask(cfg, true);
  // If a startup snapshot was supplied, hand the engine the blob so the isolate
  // is created from it. NULL deleter: g_snapshot_blob (process-lifetime) owns
  // the bytes.
  if (g_have_snapshot && g_set_snapshot)
    g_set_snapshot(cfg, reinterpret_cast<const uint8_t*>(g_snapshot_blob.data()),
                   g_snapshot_blob.size(), nullptr, nullptr);
  return jsi_no_error;
}

//==========================================================================
// Private run-envelope plumbing (design §10). The worker channel carries opaque
// string/binary frames; a coordinator-driven run multiplexes per-run control
// through the neutral run-envelope codec that rides those frames. The guest can
// never set env_type: the engine (trusted) wraps all guest output as RELAY and
// emits RESULT/RUN_ERROR itself. The dev-ambient path (no active run) stays bare.
//==========================================================================

// Post an encoded envelope frame on the worker channel. The carrier kind is
// binary; the coordinator decodes any string/binary frame as an envelope
// (design §8.3), so the carrier kind is not itself semantic.
sbox_status PostEnvelope(const v8host::RunEnvelope& env) {
  const std::vector<uint8_t> frame = v8host::EncodeRunEnvelope(env);
  return g_api->post_message(g_worker, sbox_msg_binary, frame.data(),
                             frame.size());
}

// Route guest output (host.postMessage / postMessageBinary / a host.complete
// value). During an active run it is wrapped as a RELAY envelope scoped to that
// run; dev-ambient it is posted bare, preserving the generic smoke.
sbox_status PostGuestOutput(sbox_msg_kind kind, const void* data, size_t len) {
  if (g_active_run_id == 0)
    return g_api->post_message(g_worker, kind, data, len);
  v8host::RunEnvelope env;
  env.type = v8host::RunEnvelopeType::kRelay;
  env.run_id = g_active_run_id;
  env.relay_kind = static_cast<int32_t>(kind);
  const auto* p = static_cast<const uint8_t*>(data);
  env.payload.assign(p, p + len);
  return PostEnvelope(env);
}

// Terminal emitters (worker -> broker). RESULT carries only the disposition (no
// guest bytes, design §4.2); RUN_ERROR carries a status plus a bounded, redacted
// diagnostic — the specific JS error text is logged host-side only, never on the
// wire.
void EmitRunResult(uint32_t run_id, v8host::RunEnvelopeDisposition disposition) {
  v8host::RunEnvelope env;
  env.type = v8host::RunEnvelopeType::kResult;
  env.run_id = run_id;
  env.disposition = disposition;
  PostEnvelope(env);
}

void EmitRunError(uint32_t run_id) {
  v8host::RunEnvelope env;
  env.type = v8host::RunEnvelopeType::kRunError;
  env.run_id = run_id;
  env.status_code =
      static_cast<uint32_t>(v8host::protocol::StatusCode::ERROR_INTERNAL);
  env.message = "guest run failed";  // redacted; detail stays in the host log
  PostEnvelope(env);
}

//==========================================================================
// The `host` JS object and the inbound-message bridge (JSI C++ API).
//==========================================================================

// Install host.postMessage(string) / host.postMessageBinary(ArrayBuffer) and
// attach `host` to the global. The host functions route to the container's
// message channel through the sbox_worker_api pointers (g_api), never the
// sandbox core. RAII manages every jsi pointer's lifetime — nothing leaks.
void InstallHostObject(Runtime& rt) {
  Object host(rt);

  host.setProperty(
      rt, "postMessage",
      Function::createFromHostFunction(
          rt, PropNameID::forAscii(rt, "postMessage"), 1,
          [](Runtime& rt, const Value&, const Value* args,
             size_t count) -> Value {
            MarkFirstPost();
            if (count >= 1 && args[0].isString()) {
              std::string s = args[0].getString(rt).utf8(rt);
              const sbox_status result =
                  PostGuestOutput(sbox_msg_string, s.data(), s.size());
              if (result != sbox_ok) {
                throw JSError(rt, "host.postMessage failed: result=" +
                                     std::to_string(static_cast<int>(result)));
              }
            }
            return Value::undefined();
          }));

  host.setProperty(
      rt, "postMessageBinary",
      Function::createFromHostFunction(
          rt, PropNameID::forAscii(rt, "postMessageBinary"), 1,
          [](Runtime& rt, const Value&, const Value* args,
             size_t count) -> Value {
            MarkFirstPost();
            if (count >= 1 && args[0].isObject()) {
              Object o = args[0].getObject(rt);
              if (o.isArrayBuffer(rt)) {
                ArrayBuffer ab = o.getArrayBuffer(rt);
                const sbox_status result =
                    PostGuestOutput(sbox_msg_binary, ab.data(rt), ab.size(rt));
                if (result != sbox_ok) {
                  throw JSError(rt, "host.postMessageBinary failed: result=" +
                                       std::to_string(static_cast<int>(result)));
                }
              }
            }
            return Value::undefined();
          }));

  // host.complete(optionalValue): the neutral run-completion signal (design
  // §10.3). Any provided string/ArrayBuffer rides the ordinary RELAY path first
  // (RESULT carries no guest bytes); then the run loop emits RESULT(kCompleted).
  // Dev-ambient (no active run) it just posts any value bare and is otherwise a
  // no-op, since only a coordinator run has a RESULT channel.
  host.setProperty(
      rt, "complete",
      Function::createFromHostFunction(
          rt, PropNameID::forAscii(rt, "complete"), 1,
          [](Runtime& rt, const Value&, const Value* args,
             size_t count) -> Value {
            if (count >= 1) {
              if (args[0].isString()) {
                std::string s = args[0].getString(rt).utf8(rt);
                PostGuestOutput(sbox_msg_string, s.data(), s.size());
              } else if (args[0].isObject()) {
                Object o = args[0].getObject(rt);
                if (o.isArrayBuffer(rt)) {
                  ArrayBuffer ab = o.getArrayBuffer(rt);
                  PostGuestOutput(sbox_msg_binary, ab.data(rt), ab.size(rt));
                }
              }
            }
            g_run_complete_requested = true;
            return Value::undefined();
          }));

  rt.global().setProperty(rt, "host", host);
}

// Deliver one inbound frame to JS host.onmessage (string -> JS string,
// binary -> JS ArrayBuffer). Runs on the JS thread (the loop IS the JS thread).
void DeliverToJs(Runtime& rt, sbox_msg_kind kind, const void* data,
                 size_t len) {
  Value host_v = rt.global().getProperty(rt, "host");
  if (!host_v.isObject())
    return;
  Object host = host_v.getObject(rt);
  Value cb_v = host.getProperty(rt, "onmessage");
  if (!cb_v.isObject())
    return;  // not set yet
  Object cb_obj = cb_v.getObject(rt);
  if (!cb_obj.isFunction(rt))
    return;
  Function cb = cb_obj.getFunction(rt);

  if (kind == sbox_msg_string) {
    cb.call(rt, String::createFromUtf8(rt, static_cast<const uint8_t*>(data),
                                       len));
  } else {
    // Allocate the ArrayBuffer IN-CAGE via JS `new ArrayBuffer(n)` and copy the
    // frame in. Do NOT hand V8 an external backing store: when the V8 in-process
    // sandbox is enabled, external backing stores are a FATAL error. A
    // JS-allocated buffer uses V8's in-cage allocator and works in both sandbox
    // and non-sandbox builds.
    Function ab_ctor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
    ArrayBuffer ab = ab_ctor.callAsConstructor(rt, Value(static_cast<double>(len)))
                         .getObject(rt)
                         .getArrayBuffer(rt);
    if (len)
      std::memcpy(ab.data(rt), data, len);
    cb.call(rt, std::move(ab));
  }
}

// True iff host.onmessage is currently a callable function. Used to detect a run
// that completed by top-level return without installing a handler.
bool HasOnMessageHandler(Runtime& rt) {
  Value host_v = rt.global().getProperty(rt, "host");
  if (!host_v.isObject())
    return false;
  Object host = host_v.getObject(rt);
  Value cb_v = host.getProperty(rt, "onmessage");
  return cb_v.isObject() && cb_v.getObject(rt).isFunction(rt);
}

// Clear host.onmessage so a prior run's handler cannot leak into the next run
// started on the same warmed runtime (design §10.3 "reset host handlers").
void ResetHostHandlers(Runtime& rt) {
  Value host_v = rt.global().getProperty(rt, "host");
  if (host_v.isObject())
    host_v.getObject(rt).setProperty(rt, "onmessage", Value::undefined());
}

// Run-loop context: the runtime, the dev-ambient scorecard, a fatal-failure
// flag, and the per-run dispatch state (design §10.3-§10.4). pending_starts is
// the admitted-but-not-yet-begun START FIFO; the loop begins one run at a time
// (serialized over the single JS thread). cancel/error are set while servicing
// the active run and drive its terminal.
struct RunLoopCtx {
  Runtime* rt = nullptr;
  int strings = 0;   // dev-ambient bare frames delivered to host.onmessage
  int binaries = 0;
  bool failed = false;  // fatal engine failure (dev-ambient path)
  std::deque<v8host::RunEnvelope> pending_starts;
  bool cancel_active = false;  // CANCEL seen for the active run
  bool run_error = false;      // uncaught JS error in the active run
};

// Deliver a bare dev-ambient frame to host.onmessage (string/binary), counting
// it for the scorecard. Fatal on an invalid kind or a thrown handler, exactly as
// before the run-dispatch rework.
void DeliverAmbient(RunLoopCtx* c, sbox_msg_kind kind, const void* data,
                    size_t len) {
  if (kind == sbox_msg_string)
    ++c->strings;
  else if (kind == sbox_msg_binary)
    ++c->binaries;
  else {
    printf("[v8host] invalid inbound message kind=%d\n", kind);
    c->failed = true;
    return;
  }
  try {
    DeliverToJs(*c->rt, kind, data, len);
  } catch (const std::exception& e) {
    printf("[v8host] onmessage threw: %s\n", e.what());
    c->failed = true;
  } catch (...) {
    printf("[v8host] onmessage threw (unknown)\n");
    c->failed = true;
  }
}

// Invoked by the container's drain_messages (C code) — exceptions must NOT cross
// back into C, so catch everything here. Branches each frame (design §10.3): a
// bare frame (no envelope magic) is the dev-ambient path; an envelope is a
// coordinator-driven START/RELAY/CANCEL.
void SBOX_CALL OnInbound(void* ctx, sbox_msg_kind kind, const void* data,
                         size_t len) {
  auto* c = static_cast<RunLoopCtx*>(ctx);
  if (c->failed)
    return;
  const auto* bytes = static_cast<const uint8_t*>(data);

  if (!v8host::IsRunEnvelope(bytes, len)) {
    DeliverAmbient(c, kind, data, len);
    return;
  }

  v8host::RunEnvelope env;
  if (!v8host::DecodeRunEnvelope(bytes, len, &env)) {
    printf("[v8host] dropping malformed run envelope (%zu bytes)\n", len);
    return;  // fail-closed: never act on an undecodable control frame
  }
  switch (env.type) {
    case v8host::RunEnvelopeType::kStart:
      // Begun by the loop; JS eval happens off the C drain callback.
      c->pending_starts.push_back(std::move(env));
      break;
    case v8host::RunEnvelopeType::kRelay: {
      // Deliver only to the active run, and only while it is still servicing (a
      // pending cancel/complete/error stops servicing, design §10.3). A relay for
      // a not-yet-active or already-finished run is dropped + logged: the
      // coordinator holds each run's relays until that run becomes active and
      // stops relaying once it terminates (design §10.4), so this drop is a
      // logged defense-in-depth whose discipline is owned + tested in slice (e).
      const bool servicing = g_active_run_id != 0 &&
                             env.run_id == g_active_run_id && !c->cancel_active &&
                             !c->run_error && !g_run_complete_requested;
      if (!servicing) {
        printf("[v8host] dropping relay for inactive run id=%u\n", env.run_id);
        break;
      }
      const sbox_msg_kind rk =
          env.relay_kind == static_cast<int32_t>(sbox_msg_binary)
              ? sbox_msg_binary
              : sbox_msg_string;
      try {
        DeliverToJs(*c->rt, rk, env.payload.data(), env.payload.size());
      } catch (const std::exception& e) {
        printf("[v8host] run onmessage threw: %s\n", e.what());
        c->run_error = true;
      } catch (...) {
        printf("[v8host] run onmessage threw (unknown)\n");
        c->run_error = true;
      }
      break;
    }
    case v8host::RunEnvelopeType::kCancel:
      if (g_active_run_id != 0 && env.run_id == g_active_run_id)
        c->cancel_active = true;
      break;
    case v8host::RunEnvelopeType::kResult:
    case v8host::RunEnvelopeType::kRunError:
      // Outbound-only (engine -> broker); a worker never receives these.
      printf("[v8host] dropping unexpected inbound envelope type=%u\n",
             static_cast<unsigned>(env.type));
      break;
  }
}

// Reset the per-run flags + active id once a run reaches a terminal, so the loop
// can dispatch the next pending START.
void FinishRun(RunLoopCtx* c) {
  g_active_run_id = 0;
  g_run_complete_requested = false;
  c->cancel_active = false;
  c->run_error = false;
}

// Emit the active run's terminal if one is due (priority: uncaught error >
// explicit complete > cancel). No-op in the dev-ambient path (no active run).
void ServiceActiveRunTerminal(RunLoopCtx* c) {
  if (g_active_run_id == 0)
    return;
  if (c->run_error) {
    EmitRunError(g_active_run_id);
    FinishRun(c);
  } else if (g_run_complete_requested) {
    EmitRunResult(g_active_run_id, v8host::RunEnvelopeDisposition::kCompleted);
    FinishRun(c);
  } else if (c->cancel_active) {
    EmitRunResult(g_active_run_id, v8host::RunEnvelopeDisposition::kCancelled);
    FinishRun(c);
  }
}

// Begin a coordinator-driven run: reset handlers, evaluate the START guest under
// the active run id (so its output wraps as RELAY), drain microtasks, then
// detect immediate completion — host.complete() during eval, a top-level return
// with no onmessage handler, or an uncaught error (RUN_ERROR). A run that
// installs a handler stays active for subsequent RELAY/CANCEL.
void BeginRun(Runtime& rt, const v8host::RunEnvelope& start, RunLoopCtx* c) {
  g_run_complete_requested = false;
  c->cancel_active = false;
  c->run_error = false;
  g_active_run_id = start.run_id;

  bool completed = false;
  try {
    ResetHostHandlers(rt);
    std::string src(start.payload.begin(), start.payload.end());
    auto buf = std::make_shared<StringBuffer>(std::move(src));
    auto prepared = rt.prepareJavaScript(buf, "run.js");
    rt.evaluatePreparedJavaScript(prepared);
    rt.drainMicrotasks();
    completed = g_run_complete_requested || !HasOnMessageHandler(rt);
  } catch (const JSError& e) {
    printf("[v8host] run JS error: %s\n", e.getMessage().c_str());
    c->run_error = true;
  } catch (const std::exception& e) {
    printf("[v8host] run exception: %s\n", e.what());
    c->run_error = true;
  } catch (...) {
    printf("[v8host] run exception (unknown)\n");
    c->run_error = true;
  }

  if (c->run_error) {
    EmitRunError(g_active_run_id);
    FinishRun(c);
  } else if (completed) {
    EmitRunResult(g_active_run_id, v8host::RunEnvelopeDisposition::kCompleted);
    FinishRun(c);
  }
}

// Built-in demo guest (used when no V8HOST_GUEST_JS is supplied): wire onmessage
// to echo each inbound message. A string becomes `js echo: <m>`; a binary tags
// byte 0 to prove JS actually read/wrote the in-cage ArrayBuffer. It does NOT
// post unprompted, so every broker request maps to exactly one reply.
const char* kDemoJs =
    "host.onmessage = function(m){"
    "  if (typeof m === 'string') { host.postMessage('js echo: ' + m); }"
    "  else { var a = new Uint8Array(m); a[0] = 0x42; host.postMessageBinary(m); }"
    "};";

}  // namespace

//==========================================================================
// PRE-lockdown. Load the engine, create the JSI runtime, install the `host`
// object. ACG forbids codegen/patching after this returns, so ALL engine setup
// (DLL load, --jitless, snapshot deserialize, runtime create) happens here.
// Returns sbox_ok on success, non-zero (fail-closed) otherwise.
//==========================================================================
sbox_status SBOX_CALL V8HostEngineWarmup(sbox_worker w,
                                         const sbox_worker_api* api) {
  if (!w || !api || api->struct_size < sizeof(sbox_worker_api))
    return sbox_error_args;
  g_worker = w;
  g_api = api;
  g_perf.init();
  const LONGLONG t_entry = g_perf.now();

  // Foreground task queue (the engine may post tasks; the run loop drains them).
  // Allocated here so it outlives warmup and is torn down in shutdown.
  g_tasks = new TaskQueue();
  ::InitializeCriticalSection(&g_tasks->cs);
  g_tasks->wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);  // auto-reset

  // The broker's configure() encoded the bound worker profile (engine DLL +
  // jitless + optional startup snapshot) into the opaque plugin_data; decode it
  // here. The SAME configure() armed ACG to match the jitless choice.
  v8host::V8HostWorkerProfileV1 prof;
  {
    const void* pd = nullptr;
    size_t pd_len = 0;
    if (api->get_plugin_data(w, &pd, &pd_len) != sbox_ok || !pd || pd_len == 0 ||
        !v8host::V8HostWorkerProfileV1::Decode(
            static_cast<const uint8_t*>(pd), pd_len, &prof)) {
      printf("[v8host] warmup: missing/invalid worker profile plugin_data\n");
      return sbox_error;
    }
  }
  const bool jitless = prof.jitless != 0;
  g_expect_acg = jitless;  // untrusted (jitless) => ACG enforced post-lockdown
  std::wstring engine_dll = Utf8ToWide(prof.engine_dll);
  printf("[v8host] tier = %s\n",
         jitless ? "Untrusted (jitless + ACG)" : "Trusted (JIT, ACG off)");
  if (engine_dll.empty()) {
    printf("[v8host] warmup: empty engine DLL in run profile\n");
    return sbox_error;
  }

  // Startup snapshot from the run profile (read NOW, pre-lockdown). A bound
  // profile with a non-empty snapshot_path REQUIRES that snapshot: an unreadable
  // path is fatal (fail-closed, design §8.6), never a silent normal-runtime
  // fallback. An empty snapshot_path means no snapshot was requested.
  const std::wstring snapshot_path = Utf8ToWide(prof.snapshot_path);
  if (!snapshot_path.empty()) {
    if (ReadFileBytes(snapshot_path, g_snapshot_blob)) {
      g_have_snapshot = true;
      printf("[v8host] startup snapshot from %ls (%zu bytes)\n",
             snapshot_path.c_str(), g_snapshot_blob.size());
    } else {
      printf("[v8host] warmup: bound startup snapshot %ls could not be read; "
             "failing closed\n", snapshot_path.c_str());
      return sbox_error;
    }
  }

  // A supplied guest selects custom-guest mode, not the built-in demo. Read it
  // NOW (pre-lockdown) — once the token is lowered the payload can no longer open
  // arbitrary files. This stays a neutral JS host: it installs the `host` object
  // and evaluates whatever guest it is handed. A requested but unreadable guest
  // is an input error; never replace it with the demo.
  std::wstring guest_js_path;
  if (!ReadGuestPath(guest_js_path)) {
    printf("[v8host] stage=guest-input environment query failed: error=%lu\n",
           ::GetLastError());
    return sbox_error;
  }
  g_use_guest_file = !guest_js_path.empty();
  if (g_use_guest_file) {
    if (!ReadFileBytes(guest_js_path, g_guest_src)) {
      printf("[v8host] stage=guest-input cannot read %ls: error=%lu\n",
             guest_js_path.c_str(), ::GetLastError());
      return sbox_error;
    }
    printf("[v8host] guest JS from %ls (%zu bytes)\n", guest_js_path.c_str(),
           g_guest_src.size());
  } else {
    g_guest_src = kDemoJs;
  }
  printf("[v8host] mode = %s\n",
         g_use_guest_file ? "custom guest" : "demo self-test");

  // Load the engine by FULL PATH (our own application directory) — never a bare
  // name (which would honor the search path / allow planting). The container
  // (broker) hardened the loader search path and verified the payload chain
  // (v8host.dll + this engine) before spawning us — the token-restricted worker
  // cannot reliably reach the crypto/catalog services to verify itself.
  auto load_engine = [](const std::wstring& name) -> HMODULE {
    const std::wstring p = sbox_harden::ExeDir() + name;
    return ::LoadLibraryExW(p.c_str(), nullptr,
                            LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
  };
  g_engine = load_engine(engine_dll);
  if (!g_engine) {
    printf("[v8host] LoadLibrary(%ls) failed: %lu\n", engine_dll.c_str(),
           ::GetLastError());
    return sbox_error;
  }
  const LONGLONG t_engine_loaded = g_perf.now();
  g_perf.emit("engine-load", t_entry, t_engine_loaded);
  printf("[v8host] engine = %ls\n", engine_dll.c_str());

  HMODULE guest = g_engine;  // RESOLVE() expects the module in `guest`
  if (jitless) {
    // Process-global flag — note the dummy argv[0] (V8 skips it).
    RESOLVE(guest, v8_jsi_set_v8_flags);
    char arg0[] = "v8host";
    char flag[] = "--jitless";
    char* flag_argv[] = {arg0, flag};
    size_t flag_argc = 2;
    p_v8_jsi_set_v8_flags(&flag_argc, flag_argv, /*remove_flags=*/true);
    printf("[v8host] --jitless %s\n",
           flag_argc == 1 ? "recognized" : "NOT recognized");
  }

  // If a startup snapshot was supplied, pre-check it against THIS engine now —
  // the process-global --jitless (if any) is set, so the version tag matches
  // what the blob was built with. A stale or cross-engine blob is dropped here
  // and we continue WITHOUT a snapshot rather than feed V8 an incompatible blob.
  if (g_have_snapshot) {
    auto p_compat = reinterpret_cast<decltype(&v8_startup_snapshot_compatible)>(
        ::GetProcAddress(guest, "v8_startup_snapshot_compatible"));
    auto p_compat_str =
        reinterpret_cast<decltype(&v8_startup_snapshot_compat_string)>(
            ::GetProcAddress(guest, "v8_startup_snapshot_compat_string"));
    if (p_compat) {
      const int code =
          p_compat(reinterpret_cast<const uint8_t*>(g_snapshot_blob.data()),
                   g_snapshot_blob.size());
      if (code != 0) {
        const char* why = p_compat_str ? p_compat_str(code) : "incompatible";
        printf("[v8host] warmup: bound startup snapshot rejected (%s); failing "
               "closed\n", why);
        g_snapshot_blob.clear();
        g_snapshot_blob.shrink_to_fit();
        return sbox_error;
      }
      printf("[v8host] startup snapshot compatible with engine\n");
    }
  }

  // Resolve the config setters the configure callback uses, then create the
  // runtime through the JSI C++ API (JsiAbiRuntime injects our JSI_ABI_VERSION).
  {
    RESOLVE(guest, v8_jsi_config_set_task_runner);
    RESOLVE(guest, v8_jsi_config_set_explicit_microtask_policy);
    g_set_task_runner = p_v8_jsi_config_set_task_runner;
    g_set_microtask = p_v8_jsi_config_set_explicit_microtask_policy;
    if (g_have_snapshot) {
      RESOLVE(guest, v8_jsi_config_set_startup_snapshot);
      g_set_snapshot = p_v8_jsi_config_set_startup_snapshot;
    }
  }
  RESOLVE(guest, v8_create_runtime);

  // makeJsiAbiRuntime + InstallHostObject use the throwing JSI C++ API; catch
  // everything so no exception crosses the extern "C" boundary (fail-closed).
  try {
    std::unique_ptr<Runtime> rt_owner = jsi::abi::makeJsiAbiRuntime(
        p_v8_create_runtime, &ConfigureRuntime, nullptr);
    if (!rt_owner) {
      printf("[v8host] makeJsiAbiRuntime failed\n");
      return sbox_error;
    }
    g_rt = rt_owner.release();  // ownership moves to g_rt; deleted in shutdown
    const LONGLONG t_runtime_created = g_perf.now();
    g_perf.emit("runtime-create", t_engine_loaded, t_runtime_created);
    printf("[v8host] v8jsi runtime created (warmup, pre-lockdown)\n");
    InstallHostObject(*g_rt);
  } catch (const JSError& e) {
    printf("[v8host] warmup JS error: %s\n", e.getMessage().c_str());
    return sbox_error;
  } catch (const std::exception& e) {
    printf("[v8host] warmup exception: %s\n", e.what());
    return sbox_error;
  }
  return sbox_ok;
}

//==========================================================================
// POST-lockdown. ACG MUST now be in force. Prove it with a FAILED executable
// allocation (observable kernel state), then evaluate the guest (interpreted
// under jitless, safe post-ACG) and own the JS thread in the message loop until
// the host closes the channel. Returns sbox_ok on clean completion.
//==========================================================================
sbox_status SBOX_CALL V8HostEngineRun(sbox_worker worker,
                                      const sbox_worker_api* api) {
  if (!worker || !api || api->struct_size < sizeof(sbox_worker_api))
    return sbox_error_args;
  g_worker = worker;
  g_api = api;

  DWORD err = ERROR_SUCCESS;
  const bool exec_post = CanAllocExecutable(&err);
  printf("[v8host] exec-alloc(post)=%s (err=%lu)\n",
         exec_post ? "ALLOWED -> ACG NOT ENFORCED"
                   : "BLOCKED (ACG in force)",
         err);
  PrintAcgStatus();
  // Gate by the bound tier (stashed in warmup). Untrusted (jitless) MUST have ACG
  // in force post-lockdown (executable alloc blocked -> error 1655); trusted (JIT)
  // MUST be able to allocate executable memory. Either inconsistency fails closed.
  if (g_expect_acg && exec_post)
    return sbox_error;  // untrusted but dynamic code allowed -> ACG failure
  if (!g_expect_acg && !exec_post)
    return sbox_error;  // trusted but executable alloc blocked -> inconsistent

  if (!g_rt) {
    printf("[v8host] run: no runtime (warmup did not complete)\n");
    return sbox_error;
  }
  Runtime& rt = *g_rt;

  const LONGLONG t_run_entry = g_perf.now();
  bool js_ok = false;
  bool host_closed = false;
  RunLoopCtx dctx{&rt};
  try {
    auto guest_buf = std::make_shared<StringBuffer>(g_guest_src);
    const char* guest_url = g_use_guest_file ? "guest.js" : "user.js";
    auto prepared = rt.prepareJavaScript(guest_buf, guest_url);
    const LONGLONG t_parsed = g_perf.now();
    g_perf.emit("parse", t_run_entry, t_parsed);
    rt.evaluatePreparedJavaScript(prepared);
    const LONGLONG t_executed = g_perf.now();
    g_perf.emit("execute", t_parsed, t_executed);
    printf("[v8host] %s JS evaluated = OK\n", g_use_guest_file ? "guest" : "user");
    rt.drainMicrotasks();
    if (g_perf.on) {
      if (g_first_post_qpc >= t_executed)
        g_perf.emit("kickoff", t_executed, g_first_post_qpc);
      else if (g_first_post_qpc != 0)
        printf("[v8host][perf] %-14s = (during execute, synchronous)\n",
               "kickoff");
    }

    // Event loop — owns the JS thread. Wait on inbound messages, engine-posted
    // foreground tasks, and the host close signal. Messaging goes through the
    // container's sbox_worker_api, never the sandbox core.
    HANDLE inbound = static_cast<HANDLE>(g_api->inbound_event(g_worker));
    HANDLE close_evt = static_cast<HANDLE>(g_api->close_event(g_worker));
    if (!inbound || !close_evt) {
      printf("[v8host] run: channel handles missing\n");
      return sbox_error;
    }
    HANDLE waits[3] = {inbound, g_tasks->wake, close_evt};
    printf("[v8host] entering JS message loop (until host closes channel)\n");
    for (;;) {
      DWORD w = ::WaitForMultipleObjects(3, waits, FALSE, INFINITE);
      const bool closing = w == WAIT_OBJECT_0 + 2;
      if (closing || w == WAIT_OBJECT_0) {
        g_api->drain_messages(g_worker, &OnInbound, &dctx);
      } else if (w == WAIT_OBJECT_0 + 1) {  // engine-posted foreground task(s)
        RunQueuedTasks(g_tasks);
      } else {
        printf("[v8host] message loop wait failed: wait=%lu error=%lu\n", w,
               w == WAIT_FAILED ? ::GetLastError() : ERROR_INVALID_FUNCTION);
        break;
      }
      if (dctx.failed)
        break;
      rt.drainMicrotasks();
      // Service the active coordinator run's terminal, then begin the next
      // admitted START while idle — but not on the closing iteration: the worker
      // is about to exit and the coordinator treats the frame absence as
      // WORKER_EXITED (design §10.3), so there is nothing to gain from starting a
      // run we would immediately abandon. Runs are serialized over the single JS
      // thread (design §10.4); a run that completes immediately loops on to the
      // next pending START. No-op for the dev-ambient smoke (no run, no STARTs).
      ServiceActiveRunTerminal(&dctx);
      while (!closing && g_active_run_id == 0 && !dctx.pending_starts.empty()) {
        v8host::RunEnvelope start = std::move(dctx.pending_starts.front());
        dctx.pending_starts.pop_front();
        BeginRun(rt, start, &dctx);
      }
      if (closing) {
        host_closed = true;
        break;
      }
    }
    js_ok = host_closed && !dctx.failed;
    printf("[v8host] JS loop exited: onmessage delivered %d string + %d binary\n",
           dctx.strings, dctx.binaries);
  } catch (const JSError& e) {
    printf("[v8host] JS error: %s\n", e.getMessage().c_str());
  } catch (const std::exception& e) {
    printf("[v8host] exception: %s\n", e.what());
  }

  printf("[v8host] RESULT: %s\n",
         js_ok ? "PASS - untrusted JS exchanges WebView2-style messages "
                 "(postMessage/onmessage) under lockdown (jitless + ACG) via "
                 "the JSI C++ API over a generic, V8-agnostic container"
               : "FAIL");
  return js_ok ? sbox_ok : sbox_error;
}

//==========================================================================
// Tear down the runtime BEFORE the task queue it references (the runtime's
// destruction fires TaskRunnerDeleteCb, which touches g_tasks), then free the
// engine handle.
//==========================================================================
void SBOX_CALL V8HostEngineShutdown(sbox_worker /*w*/) {
  if (g_rt) {
    delete g_rt;
    g_rt = nullptr;
  }
  if (g_tasks) {
    if (g_tasks->wake)
      ::CloseHandle(g_tasks->wake);
    ::DeleteCriticalSection(&g_tasks->cs);
    delete g_tasks;
    g_tasks = nullptr;
  }
  if (g_engine) {
    ::FreeLibrary(g_engine);
    g_engine = nullptr;
  }
  printf("[v8host] shutdown\n");
}

//==========================================================================
// BROKER role. Runs in the broker process (which loads this DLL only to call
// configure). On the coordinator path it decodes the V8HostSpawnConfigV1
// (session security envelope + bound effective worker profile) from
// configure_data; the standalone broker smoke passes none, so a dev fallback
// derives the tier/engine/snapshot from env + container defaults. Either way it
// drives every sbox config setter from the spawn config and encodes the
// V8HostWorkerProfileV1 into the opaque plugin_data the worker reads in warmup.
//==========================================================================

// Build the dev-fallback spawn config used when configure() is handed no
// configure_data (the standalone `sbox.exe --broker` smoke). ACG forces jitless
// for Untrusted; Trusted leaves ACG off so V8's JIT can run (ApplySpawnConfig
// enforces that jitless<->ACG match). The SBOX_TIER / V8HOST_ENGINE_DLL /
// V8HOST_SNAPSHOT overrides stay dev-test-only.
static void BuildDevSpawnConfig(v8host::V8HostSpawnConfigV1& spawn) {
  const bool trusted = EnvW(L"SBOX_TIER") == L"trusted";
  std::wstring engine = EnvW(L"V8HOST_ENGINE_DLL");
  if (engine.empty())
    engine = trusted ? L"v8jsi.dll" : L"v8jsisb.dll";
  spawn.tier = trusted ? v8host::kTierTrusted : v8host::kTierUntrusted;
  spawn.effective_tier = spawn.tier;
  spawn.prohibit_dynamic_code = !trusted;
  spawn.integrity = sbox_integrity_low;
  spawn.delayed_integrity = sbox_integrity_untrusted;
  spawn.initial_token = sbox_token_restricted_same_access;
  spawn.lockdown_token = sbox_token_lockdown;
  spawn.use_app_container = false;
  spawn.low_privilege_app_container = false;
  spawn.engine_dll = WideToUtf8(engine);
  spawn.snapshot_path = WideToUtf8(EnvW(L"V8HOST_SNAPSHOT"));
}

sbox_status SBOX_CALL V8HostEngineConfigure(sbox_config cfg,
                                            const sbox_config_api* api,
                                            const void* configure_data,
                                            size_t configure_data_size) {
  if (!cfg || !api || api->struct_size < sizeof(sbox_config_api))
    return sbox_error_args;
  if ((configure_data_size && !configure_data) ||
      configure_data_size > 64 * 1024)
    return sbox_error_args;

  v8host::V8HostSpawnConfigV1 spawn;
  if (configure_data && configure_data_size) {
    // Coordinator path: a malformed spawn config fails closed (no half-described
    // sandbox is ever spawned).
    if (!v8host::V8HostSpawnConfigV1::Decode(
            static_cast<const uint8_t*>(configure_data), configure_data_size,
            &spawn)) {
      printf("[v8host] configure: bad V8HostSpawnConfigV1\n");
      return sbox_error;
    }
  } else {
    BuildDevSpawnConfig(spawn);
  }

  // Drive every applicable config setter from the spawn config, enforce the
  // effective-tier/ACG consistency rule, and encode the worker profile into the
  // opaque plugin_data. Any rejected setter or inconsistency fails closed.
  if (!v8host::ApplySpawnConfig(spawn, api, cfg)) {
    printf("[v8host] configure: ApplySpawnConfig failed (fail closed)\n");
    return sbox_error;
  }
  return sbox_ok;
}
