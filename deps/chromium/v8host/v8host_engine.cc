// v8host_engine.cc — the REAL V8/JSI engine persona of v8host.dll, driven by the
// product sbox.exe worker over the plugin ABI. This replaces the interim
// v8host_stub.cc: it is carved from the retired v8host.exe main (the orphaned
// v8host.cc), split at the LowerToken boundary into the three plugin-ABI
// entrypoints the container resolves by name.
//
// Control inversion: the container (sbox.exe) owns main() and the sandbox
// lifecycle; this DLL links ONLY sbox_plugin_abi.h (never the sandbox core) and
// reaches the message channel through the SboxHostServices function pointers.
//
//   v8host_worker_warmup  PRE-lockdown : load the engine DLL (v8jsisb.dll jitless
//                                        for Untrusted / v8jsi.dll for Trusted),
//                                        set --jitless, (optional) startup
//                                        snapshot, read the guest JS, create the
//                                        JSI runtime, install the `host` object.
//                                        All codegen/patching happens HERE — ACG
//                                        forbids it afterward.
//   sbox_target_lower_token()           (driven by the container: ACG armed)
//   v8host_worker_run     POST-lockdown: evaluate the guest (interpreted under
//                                        jitless, safe post-ACG), then own the JS
//                                        thread in the message loop until close.
//   v8host_worker_shutdown              : tear down the runtime + engine handle.
//
// IMPORTANT: this drives v8jsi through the **JSI C++ API** (facebook::jsi via
// JsiAbiRuntime), NOT the raw ABI-safe C interface. The C ABI is the binary-
// stable boundary INSIDE the DLL; C++ consumers use jsi.h + JsiAbiRuntime.h
// (both shipped in the NuGet package). Only the config seam (the configure
// callback that wires the task runner) stays on the C ABI, because that IS the
// ABI boundary.

// V8HOST_PLUGIN_IMPL (set by the BUILD.gn target) makes sbox_plugin_abi.h declare
// the exported v8host_worker_* prototypes this TU defines.
#include "sbox_plugin_abi.h"

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
const SboxHostServices* g_host = nullptr;  // message channel (never sbox core)
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
    return 21;                                                           \
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
// The `host` JS object and the inbound-message bridge (JSI C++ API).
//==========================================================================

// Install host.postMessage(string) / host.postMessageBinary(ArrayBuffer) and
// attach `host` to the global. The host functions route to the container's
// message channel through the SboxHostServices pointers (g_host), never the
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
              const int result = g_host->post_message(
                  g_host->target, SBOX_PLUGIN_MSG_STRING, s.data(), s.size());
              if (result != 0) {
                throw JSError(rt, "host.postMessage failed: result=" +
                                     std::to_string(result));
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
                const int result = g_host->post_message(
                    g_host->target, SBOX_PLUGIN_MSG_BINARY, ab.data(rt),
                    ab.size(rt));
                if (result != 0) {
                  throw JSError(rt, "host.postMessageBinary failed: result=" +
                                       std::to_string(result));
                }
              }
            }
            return Value::undefined();
          }));

  rt.global().setProperty(rt, "host", host);
}

// Deliver one inbound frame to JS host.onmessage (string -> JS string,
// binary -> JS ArrayBuffer). Runs on the JS thread (the loop IS the JS thread).
void DeliverToJs(Runtime& rt, int kind, const void* data, size_t len) {
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

  if (kind == SBOX_PLUGIN_MSG_STRING) {
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

// Drain context: the runtime + counts of what JS received (for the scorecard).
struct DrainCtx {
  Runtime* rt;
  int strings = 0;
  int binaries = 0;
  bool failed = false;
};

// Invoked by the container's drain_messages (C code) — exceptions must NOT cross
// back into C, so catch everything here.
void OnInbound(void* ctx, int kind, const void* data, size_t len) {
  auto* c = static_cast<DrainCtx*>(ctx);
  if (c->failed)
    return;
  if (kind == SBOX_PLUGIN_MSG_STRING)
    ++c->strings;
  else if (kind == SBOX_PLUGIN_MSG_BINARY)
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
// Returns 0 on success, non-zero (fail-closed) otherwise.
//==========================================================================
extern "C" __declspec(dllexport) int v8host_worker_warmup(
    const SboxHostServices* host) {
  if (!host || host->struct_size < sizeof(SboxHostServices))
    return 1;
  g_host = host;
  g_perf.init();
  const LONGLONG t_entry = g_perf.now();

  // Foreground task queue (the engine may post tasks; the run loop drains them).
  // Allocated here so it outlives warmup and is torn down in shutdown.
  g_tasks = new TaskQueue();
  ::InitializeCriticalSection(&g_tasks->cs);
  g_tasks->wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);  // auto-reset

  // Tier selection (host-chosen via SBOX_TIER, inherited from the broker):
  //   Untrusted (default) = jitless + ACG (V8 emits no executable code).
  //   Trusted             = JIT allowed; the broker also leaves ACG off.
  const bool trusted_tier = EnvW(L"SBOX_TIER") == L"trusted";
  printf("[v8host] tier = %s\n",
         trusted_tier ? "Trusted (JIT, ACG off)" : "Untrusted (jitless + ACG)");

  // Engine selection: Untrusted runs the jitless sandbox engine v8jsisb.dll (the
  // product default); Trusted runs the full-JIT v8jsi.dll. V8HOST_ENGINE_DLL
  // overrides the filename. If the tier default is absent, fall back to v8jsi.dll
  // so a single-engine layout still runs.
  std::wstring engine_dll = EnvW(L"V8HOST_ENGINE_DLL");
  const bool engine_overridden = !engine_dll.empty();
  if (engine_dll.empty())
    engine_dll = trusted_tier ? L"v8jsi.dll" : L"v8jsisb.dll";

  // Host-supplied startup snapshot: if V8HOST_SNAPSHOT names a readable file,
  // read the blob NOW (pre-lockdown) and create the runtime from it below. A
  // set-but-unreadable path is a warning, not fatal (falls back to a normal
  // runtime). The blob is held for the process lifetime.
  const std::wstring snapshot_path = EnvW(L"V8HOST_SNAPSHOT");
  if (!snapshot_path.empty()) {
    if (ReadFileBytes(snapshot_path, g_snapshot_blob)) {
      g_have_snapshot = true;
      printf("[v8host] startup snapshot from %ls (%zu bytes)\n",
             snapshot_path.c_str(), g_snapshot_blob.size());
    } else {
      printf("[v8host] WARNING: V8HOST_SNAPSHOT=%ls could not be read; "
             "creating a normal runtime\n", snapshot_path.c_str());
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
    return 24;
  }
  g_use_guest_file = !guest_js_path.empty();
  if (g_use_guest_file) {
    if (!ReadFileBytes(guest_js_path, g_guest_src)) {
      printf("[v8host] stage=guest-input cannot read %ls: error=%lu\n",
             guest_js_path.c_str(), ::GetLastError());
      return 24;
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
  if (!g_engine && !engine_overridden && engine_dll != L"v8jsi.dll") {
    printf("[v8host] %ls not found, falling back to v8jsi.dll\n",
           engine_dll.c_str());
    engine_dll = L"v8jsi.dll";
    g_engine = load_engine(engine_dll);
  }
  if (!g_engine) {
    printf("[v8host] LoadLibrary(%ls) failed: %lu\n", engine_dll.c_str(),
           ::GetLastError());
    return 20;
  }
  const LONGLONG t_engine_loaded = g_perf.now();
  g_perf.emit("engine-load", t_entry, t_engine_loaded);
  printf("[v8host] engine = %ls\n", engine_dll.c_str());

  HMODULE guest = g_engine;  // RESOLVE() expects the module in `guest`
  if (!trusted_tier) {
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
        printf("[v8host] WARNING: startup snapshot rejected (%s); continuing "
               "without it\n", why);
        g_have_snapshot = false;
        g_snapshot_blob.clear();
        g_snapshot_blob.shrink_to_fit();
      } else {
        printf("[v8host] startup snapshot compatible with engine\n");
      }
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
      return 22;
    }
    g_rt = rt_owner.release();  // ownership moves to g_rt; deleted in shutdown
    const LONGLONG t_runtime_created = g_perf.now();
    g_perf.emit("runtime-create", t_engine_loaded, t_runtime_created);
    printf("[v8host] v8jsi runtime created (warmup, pre-lockdown)\n");
    InstallHostObject(*g_rt);
  } catch (const JSError& e) {
    printf("[v8host] warmup JS error: %s\n", e.getMessage().c_str());
    return 25;
  } catch (const std::exception& e) {
    printf("[v8host] warmup exception: %s\n", e.what());
    return 25;
  }
  return 0;
}

//==========================================================================
// POST-lockdown. ACG MUST now be in force. Prove it with a FAILED executable
// allocation (observable kernel state), then evaluate the guest (interpreted
// under jitless, safe post-ACG) and own the JS thread in the message loop until
// the host closes the channel. Returns 0 on clean completion.
//==========================================================================
extern "C" __declspec(dllexport) int v8host_worker_run(
    const SboxHostServices* host) {
  if (!host)
    return 1;
  g_host = host;

  DWORD err = ERROR_SUCCESS;
  const bool exec_post = CanAllocExecutable(&err);
  printf("[v8host] exec-alloc(post)=%s (err=%lu)\n",
         exec_post ? "ALLOWED -> ACG NOT ENFORCED"
                   : "BLOCKED (ACG in force)",
         err);
  PrintAcgStatus();
  if (exec_post)
    return 3;  // dynamic code allowed post-lockdown -> ACG failure

  if (!g_rt) {
    printf("[v8host] run: no runtime (warmup did not complete)\n");
    return 2;
  }
  Runtime& rt = *g_rt;

  const LONGLONG t_run_entry = g_perf.now();
  bool js_ok = false;
  bool host_closed = false;
  DrainCtx dctx{&rt};
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
    // container's SboxHostServices, never the sandbox core.
    HANDLE inbound = static_cast<HANDLE>(g_host->inbound_event(g_host->target));
    HANDLE close_evt = static_cast<HANDLE>(g_host->close_event(g_host->target));
    if (!inbound || !close_evt) {
      printf("[v8host] run: channel handles missing\n");
      return 4;
    }
    HANDLE waits[3] = {inbound, g_tasks->wake, close_evt};
    printf("[v8host] entering JS message loop (until host closes channel)\n");
    for (;;) {
      DWORD w = ::WaitForMultipleObjects(3, waits, FALSE, INFINITE);
      const bool closing = w == WAIT_OBJECT_0 + 2;
      if (closing || w == WAIT_OBJECT_0) {
        g_host->drain_messages(g_host->target, &OnInbound, &dctx);
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
  return js_ok ? 0 : 6;
}

//==========================================================================
// Tear down the runtime BEFORE the task queue it references (the runtime's
// destruction fires TaskRunnerDeleteCb, which touches g_tasks), then free the
// engine handle.
//==========================================================================
extern "C" __declspec(dllexport) void v8host_worker_shutdown(void) {
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
