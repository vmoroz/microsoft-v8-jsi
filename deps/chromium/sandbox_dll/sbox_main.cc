// sbox_main.cc — the product single-image sbox.exe: one binary that is BOTH the
// sandbox broker and the sandbox worker, selected by argv. It statically links
// the same Chromium sandbox core as the DLL did (via sbox_dll.cc) so the broker
// and worker share one image and one set of sandbox globals.
//
// Personas (role is chosen first; neither falls through into the other's init).
// The app-specific behavior lives in a plugin DLL named by --plugin (resolved by
// name via the sbox.h plugin ABI); sbox.exe itself stays generic + app-agnostic:
//   sbox.exe --broker --plugin <dll>  : load+verify the plugin, plugin.configure
//                         supplies the sandbox policy, spawn "<self> --worker",
//                         round-trip. Drives sbox_broker_* + the plugin's configure.
//   sbox.exe --worker --plugin <dll>  : sbox_target_begin -> plugin.warmup ->
//                         lower_token -> plugin.run -> plugin.shutdown.
//   sbox.exe --broker-service / --client / --pipe-bench : the shared-broker
//                         rendezvous + a transport-latency probe (used by later
//                         stages).
//
// SBOX_API is plain extern "C" here (the target defines SBOX_STATIC), so the
// sbox_* core compiled into this EXE stays out of its export table.
#include "sbox_core_internal.h"
#include "sbox_harden.h"
#include "sbox.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <atomic>
#include <memory>
#include <string>
#include <vector>

// Same-image seed: the broker writes this worker's sandbox globals + message
// channel directly at their shared RVAs while the worker is suspended, so there
// is no exported bootstrap struct and no export-table walk. sbox_target_begin
// adopts that seed (and fails closed if its magic is absent).

// The host's private definitions of sbox.h's opaque handles. Defined at GLOBAL
// scope (matching sbox.h's forward declarations), not in the anonymous namespace
// below, so they are the SAME ::sbox_config_s / ::sbox_worker_s the typedefs name.

// sbox_config: the broker's policy builder. plugin.configure() writes into it via
// the sbox_config_api setters; PrepareSandbox then marshals it to an SboxPolicy.
struct sbox_config_s {
  bool acg = false;
  int initial_integrity = SBOX_INTEGRITY_LOW;
  int delayed_integrity = SBOX_INTEGRITY_UNTRUSTED;
  std::vector<std::wstring> file_patterns;
  std::vector<int> file_readonly;
  std::vector<std::wstring> capabilities;
  bool use_app_container = false;
  bool lpac = false;
  std::wstring profile;
  std::vector<std::wstring> engine_dlls;  // verified by the broker before spawn
  std::string plugin_data;                // opaque app blob, carried to the worker
};

// sbox_worker: the worker's run context — just the sandbox target the worker_api
// services bridge to.
struct sbox_worker_s {
  SboxTarget* target = nullptr;
};

namespace {

// Worker exit codes (the broker asserts 0). Distinct values make a failed run
// self-describing in the captured worker log.
enum WorkerExit {
  kOk = 0,
  kBeginFailed = 10,
  kPingPreFailed = 11,
  kDllLoadFailed = 12,
  kDllResolveFailed = 13,
  kWarmupFailed = 14,
  kLowerTokenFailed = 15,
  kPingPostFailed = 16,
  kRunFailed = 17,  // plugin.run returned non-sbox_ok (see worker log; e.g. ACG not enforced)
};

std::wstring SelfPath() {
  wchar_t buf[MAX_PATH] = {};
  const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
  return std::wstring(buf, n);
}

// A plugin name must be a BARE app-dir filename (e.g. "v8host.dll") — never a
// path. The broker Authenticode-verifies it inside the app dir, so rejecting
// separators / ".." closes the only planting vector the name itself could open.
bool IsBareFilename(const std::wstring& name) {
  return !name.empty() && name.find_first_of(L"\\/:") == std::wstring::npos &&
         name.find(L"..") == std::wstring::npos;
}

// Widen a narrow argv token (plugin names are ASCII; UTF-8 is a safe superset).
std::wstring Widen(const char* s) {
  if (!s || !*s)
    return std::wstring();
  const int n = ::MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
  if (n <= 1)
    return std::wstring();
  std::wstring w(static_cast<size_t>(n - 1), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
  return w;
}

// Parse the plugin DLL name. Accepts both "--plugin <name>" (manual CLI) and the
// "--plugin=<name>" spelling base::CommandLine renders when the broker propagates
// it to the worker. Returns "" if absent.
std::wstring ParsePluginName(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--plugin") == 0)
      return (i + 1 < argc) ? Widen(argv[i + 1]) : std::wstring();
    if (std::strncmp(argv[i], "--plugin=", 9) == 0)
      return Widen(argv[i] + 9);
  }
  return std::wstring();
}

// ===== the sbox.h plugin ABI, host side =====
// sbox.exe is a generic container; the plugin DLL (resolved by --plugin) carries
// all app knowledge. The broker calls plugin.configure to collect the sandbox
// policy; the worker drives warmup -> lower_token -> run -> shutdown.

// The plugin passes sbox.h's integrity constants; pin them to the core's enum.
static_assert(static_cast<int>(sbox_integrity_low) ==
                      static_cast<int>(SBOX_INTEGRITY_LOW) &&
                  static_cast<int>(sbox_integrity_untrusted) ==
                      static_cast<int>(SBOX_INTEGRITY_UNTRUSTED),
              "sbox.h integrity levels must match SboxIntegrityLevel");

// WkDrainMessages hands the plugin's sbox_message_cb to the core's drain, which
// calls it as SboxMessageCb; the two differ only in the kind parameter type
// (sbox_msg_kind vs int), so that must stay ABI-identical.
static_assert(sizeof(sbox_msg_kind) == sizeof(int) &&
                  static_cast<int>(sbox_msg_string) ==
                      static_cast<int>(SBOX_MSG_STRING) &&
                  static_cast<int>(sbox_msg_binary) ==
                      static_cast<int>(SBOX_MSG_BINARY),
              "sbox_msg_kind must match SboxMsgKind for the drain cast");

// --- sbox_config_api: broker services the plugin's configure() calls ---
void SBOX_CALL CfgSetAcg(sbox_config c, int enable) {
  if (c)
    c->acg = enable != 0;
}
void SBOX_CALL CfgSetIntegrity(sbox_config c, int initial, int delayed) {
  if (!c)
    return;
  c->initial_integrity = initial;
  c->delayed_integrity = delayed;
}
sbox_status SBOX_CALL CfgAddFileRule(sbox_config c, const wchar_t* pattern,
                                     int readonly) {
  if (!c || !pattern || !pattern[0])
    return sbox_error_args;
  c->file_patterns.emplace_back(pattern);
  c->file_readonly.push_back(readonly ? 1 : 0);
  return sbox_ok;
}
sbox_status SBOX_CALL CfgAddCapability(sbox_config c, const wchar_t* sid) {
  if (!c || !sid || !sid[0])
    return sbox_error_args;
  c->capabilities.emplace_back(sid);
  return sbox_ok;
}
void SBOX_CALL CfgSetAppContainer(sbox_config c, int enable, int lpac,
                                  const wchar_t* profile) {
  if (!c)
    return;
  c->use_app_container = enable != 0;
  c->lpac = lpac != 0;
  c->profile = profile ? profile : L"";
}
sbox_status SBOX_CALL CfgAllowEngineDll(sbox_config c, const wchar_t* filename) {
  if (!c || !filename || !IsBareFilename(filename))
    return sbox_error_args;
  c->engine_dlls.emplace_back(filename);
  return sbox_ok;
}
void SBOX_CALL CfgSetPluginData(sbox_config c, const void* data, size_t len) {
  if (!c)
    return;
  if (data && len)
    c->plugin_data.assign(static_cast<const char*>(data), len);
  else
    c->plugin_data.clear();
}

sbox_config_api MakeConfigApi() {
  sbox_config_api api = {};
  api.struct_size = sizeof(api);
  api.set_acg = &CfgSetAcg;
  api.set_integrity = &CfgSetIntegrity;
  api.add_file_rule = &CfgAddFileRule;
  api.add_capability = &CfgAddCapability;
  api.set_app_container = &CfgSetAppContainer;
  api.allow_engine_dll = &CfgAllowEngineDll;
  api.set_plugin_data = &CfgSetPluginData;
  return api;
}

// --- sbox_worker_api: worker services the plugin's warmup()/run() call, bridged
// to the sandbox core's sbox_target_* message channel ---
sbox_status SBOX_CALL WkGetPluginData(sbox_worker w, const void** data,
                                      size_t* len) {
  if (!w || !w->target || !data || !len)
    return sbox_error_args;
  return sbox_target_plugin_data(w->target, data, len) ? sbox_ok : sbox_error;
}
int SBOX_CALL WkAcgEnabled(sbox_worker w) {
  return (w && w->target) ? sbox_target_acg_enabled(w->target) : 0;
}
sbox_status SBOX_CALL WkPostMessage(sbox_worker w, sbox_msg_kind kind,
                                    const void* data, size_t len) {
  if (!w || !w->target)
    return sbox_error_args;
  return sbox_target_post_message(w->target, static_cast<int>(kind), data,
                                  len) == 0
             ? sbox_ok
             : sbox_error;
}
void* SBOX_CALL WkInboundEvent(sbox_worker w) {
  return (w && w->target) ? sbox_target_inbound_event(w->target) : nullptr;
}
sbox_status SBOX_CALL WkDrainMessages(sbox_worker w, sbox_message_cb cb,
                                      void* ctx) {
  if (!w || !w->target || !cb)
    return sbox_error_args;
  // sbox_message_cb and SboxMessageCb differ only in the kind parameter's type
  // (sbox_msg_kind vs int) — ABI-identical, so the reinterpret_cast is safe.
  sbox_target_drain_messages(w->target, reinterpret_cast<SboxMessageCb>(cb), ctx);
  return sbox_ok;
}
void* SBOX_CALL WkCloseEvent(sbox_worker w) {
  return (w && w->target) ? sbox_target_close_event(w->target) : nullptr;
}

sbox_worker_api MakeWorkerApi() {
  sbox_worker_api api = {};
  api.struct_size = sizeof(api);
  api.get_plugin_data = &WkGetPluginData;
  api.acg_enabled = &WkAcgEnabled;
  api.post_message = &WkPostMessage;
  api.inbound_event = &WkInboundEvent;
  api.drain_messages = &WkDrainMessages;
  api.close_event = &WkCloseEvent;
  return api;
}

// Load a --plugin DLL and hand back its validated sbox_plugin vtable. The broker
// runs UNRESTRICTED, so IT (not the sandbox worker, which cannot reliably reach
// the crypto/catalog services once locked down) Authenticode-verifies the DLL
// BEFORE load; the worker re-resolves the already-verified DLL with verify=false.
// Dev builds tolerate UNSIGNED only via SBOX_DEV_ALLOW_UNSIGNED (no runtime
// bypass).
bool LoadPlugin(const std::wstring& plugin_name, bool verify, const char* tag,
                HMODULE* out_mod, const sbox_plugin** out_vtable) {
  if (!IsBareFilename(plugin_name)) {
    printf("[sbox] %s: invalid --plugin name (bare app-dir filename only)\n",
           tag);
    return false;
  }
  const std::wstring full = sbox_harden::ExeDir() + plugin_name;
  if (verify && !sbox_harden::CheckTrust(full, tag)) {
    printf("[sbox] %s: signature verification failed: %ls\n", tag,
           plugin_name.c_str());
    return false;
  }
  HMODULE mod = ::LoadLibraryExW(full.c_str(), nullptr,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                     LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
  if (!mod) {
    printf("[sbox] %s: LoadLibrary(%ls) failed: %lu\n", tag,
           plugin_name.c_str(), ::GetLastError());
    return false;
  }
  auto entry = reinterpret_cast<sbox_plugin_main_fn>(
      ::GetProcAddress(mod, SBOX_PLUGIN_ENTRY));
  const sbox_plugin* vtable = nullptr;
  if (!entry || entry(SBOX_ABI_VERSION, &vtable) != sbox_ok || !vtable) {
    printf("[sbox] %s: %s did not return a plugin\n", tag, SBOX_PLUGIN_ENTRY);
    ::FreeLibrary(mod);
    return false;
  }
  if (vtable->abi_version != SBOX_ABI_VERSION ||
      vtable->struct_size < sizeof(sbox_plugin) || !vtable->configure ||
      !vtable->warmup || !vtable->run || !vtable->shutdown) {
    printf("[sbox] %s: plugin ABI mismatch (abi=%u host=%u) or incomplete "
           "vtable\n",
           tag, vtable->abi_version, SBOX_ABI_VERSION);
    ::FreeLibrary(mod);
    return false;
  }
  *out_mod = mod;
  *out_vtable = vtable;
  return true;
}

// The broker's prepared sandbox: the plugin vtable + the SboxPolicy it described,
// with all pointer-referenced storage owned here. Must outlive every spawn that
// uses `policy` (its pointers alias the members below), so never copy it after
// PrepareSandbox fills it.
struct PreparedSandbox {
  HMODULE plugin_mod = nullptr;
  const sbox_plugin* plugin = nullptr;
  std::wstring plugin_name;
  sbox_config_s cfg;                     // collected by configure()
  std::vector<SboxFileRule> file_rules;  // pattern ptrs into cfg.file_patterns
  std::vector<const wchar_t*> cap_ptrs;  // into cfg.capabilities
  SboxPolicy policy = {};

  PreparedSandbox() = default;
  // policy aliases the members above, so a copy/move would leave it dangling.
  PreparedSandbox(const PreparedSandbox&) = delete;
  PreparedSandbox& operator=(const PreparedSandbox&) = delete;
};

// Resolve+verify the plugin, run configure() to collect the policy, verify every
// declared engine DLL, and build the SboxPolicy. Returns false (fail closed) on
// any error.
bool PrepareSandbox(const std::wstring& plugin_name, PreparedSandbox& out) {
  if (!LoadPlugin(plugin_name, /*verify=*/true, "plugin", &out.plugin_mod,
                  &out.plugin))
    return false;
  out.plugin_name = plugin_name;

  // BROKER role: the plugin describes the sandbox it needs.
  sbox_config_api api = MakeConfigApi();
  const sbox_status cs = out.plugin->configure(&out.cfg, &api);
  if (cs != sbox_ok) {
    printf("[sbox] plugin.configure failed: status=%d\n", cs);
    return false;
  }

  // Verify each engine DLL the worker will LoadLibrary pre-lockdown.
  const std::wstring dir = sbox_harden::ExeDir();
  for (const std::wstring& dll : out.cfg.engine_dlls) {
    if (!IsBareFilename(dll) || !sbox_harden::CheckTrust(dir + dll, "engine")) {
      printf("[sbox] engine DLL verification failed: %ls\n", dll.c_str());
      return false;
    }
  }

  // Marshal the collected config into an SboxPolicy. Token levels are the
  // container's default (ordinary restricted-token mode); the plugin owns ACG,
  // integrity, AppContainer, file rules, capabilities, and the opaque blob.
  SboxPolicy& p = out.policy;
  p = {};
  p.struct_size = sizeof(p);
  p.initial_token = SBOX_TOKEN_RESTRICTED_SAME_ACCESS;
  p.lockdown_token = SBOX_TOKEN_LOCKDOWN;
  p.integrity = out.cfg.initial_integrity;
  p.delayed_integrity = out.cfg.delayed_integrity;
  p.prohibit_dynamic_code = out.cfg.acg ? 1 : 0;
  for (size_t i = 0; i < out.cfg.file_patterns.size(); ++i) {
    SboxFileRule r = {};
    r.pattern = out.cfg.file_patterns[i].c_str();
    r.readonly = out.cfg.file_readonly[i];
    out.file_rules.push_back(r);
  }
  p.file_rules = out.file_rules.empty() ? nullptr : out.file_rules.data();
  p.file_rule_count = out.file_rules.size();
  p.use_app_container = out.cfg.use_app_container ? 1 : 0;
  p.low_privilege_app_container = out.cfg.lpac ? 1 : 0;
  p.app_container_profile_name =
      out.cfg.profile.empty() ? nullptr : out.cfg.profile.c_str();
  for (const std::wstring& cap : out.cfg.capabilities)
    out.cap_ptrs.push_back(cap.c_str());
  p.capabilities = out.cap_ptrs.empty() ? nullptr : out.cap_ptrs.data();
  p.capability_count = out.cap_ptrs.size();
  p.worker_plugin_name = out.plugin_name.c_str();
  p.plugin_data =
      out.cfg.plugin_data.empty() ? nullptr : out.cfg.plugin_data.data();
  p.plugin_data_len = out.cfg.plugin_data.size();
  return true;
}

// Worker persona: sbox.exe owns the lifecycle and calls into the plugin at the
// ACG-correct points (warmup PRE-lockdown, run POST-lockdown). This is the
// control inversion from a payload that owns main().
int RunWorker(const std::wstring& plugin_name) {
  printf("[sbox] role=worker pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();

  SboxTarget* target = sbox_target_begin();
  if (!target) {
    printf("[sbox] worker: sbox_target_begin failed\n");
    return kBeginFailed;
  }
  const bool ping_pre = sbox_target_test_ipc(target) != 0;
  printf("[sbox] worker: IPC pre-lockdown = %s\n", ping_pre ? "OK" : "FAIL");

  // Load the broker-verified plugin by FULL PATH from our own app dir (PRE-
  // lockdown: the lowered token can no longer open it) and resolve its vtable.
  // The broker already Authenticode-verified it, so the worker just re-resolves.
  HMODULE plugin_mod = nullptr;
  const sbox_plugin* plugin = nullptr;
  if (!LoadPlugin(plugin_name, /*verify=*/false, "worker-plugin", &plugin_mod,
                  &plugin))
    return kDllResolveFailed;

  sbox_worker_s wk;
  wk.target = target;
  const sbox_worker_api wapi = MakeWorkerApi();

  // warmup (PRE-lockdown) -> lower_token -> run (POST-lockdown) -> shutdown.
  const sbox_status warmup_rc = plugin->warmup(&wk, &wapi);
  printf("[sbox] worker: plugin.warmup -> %d\n", warmup_rc);
  if (warmup_rc != sbox_ok)
    return kWarmupFailed;

  const int lowered = sbox_target_lower_token(target);
  if (lowered != 0) {
    printf("[sbox] worker: sbox_target_lower_token failed (%d)\n", lowered);
    return kLowerTokenFailed;
  }
  printf("[sbox] worker: LowerToken survived\n");

  const bool ping_post = sbox_target_test_ipc(target) != 0;
  printf("[sbox] worker: IPC post-lockdown = %s\n", ping_post ? "OK" : "FAIL");

  const sbox_status run_rc = plugin->run(&wk, &wapi);
  printf("[sbox] worker: plugin.run -> %d\n", run_rc);

  plugin->shutdown(&wk);
  sbox_target_end(target);

  if (!ping_pre)
    return kPingPreFailed;
  if (!ping_post)
    return kPingPostFailed;
  if (run_rc != sbox_ok)
    return kRunFailed;
  return kOk;
}

// --- broker ---

struct BrokerMsgCtx {
  HANDLE reply_event = nullptr;
  int replies = 0;
  bool unexpected = false;
  std::string last_reply;  // worker reply text, forwarded to the pipe client
};

void OnBrokerReply(void* ctx, int kind, const void* data, size_t len) {
  auto* c = static_cast<BrokerMsgCtx*>(ctx);
  if (kind == SBOX_MSG_STRING) {
    const std::string text(static_cast<const char*>(data), len);
    printf("[sbox] broker: worker reply = \"%s\"\n", text.c_str());
    // The worker runs real guest JS under lockdown; the built-in demo guest
    // echoes each request as "js echo: <request>" via host.postMessage.
    if (text.rfind("js echo: ", 0) == 0) {
      ++c->replies;
      c->last_reply = text;
    } else {
      c->unexpected = true;
    }
  } else {
    c->unexpected = true;
  }
  if (c->reply_event) ::SetEvent(c->reply_event);
}

// High-resolution timer for the latency measurement.
struct Perf {
  LARGE_INTEGER freq;
  Perf() { ::QueryPerformanceFrequency(&freq); }
  LONGLONG now() const {
    LARGE_INTEGER t;
    ::QueryPerformanceCounter(&t);
    return t.QuadPart;
  }
  double ms(LONGLONG a, LONGLONG b) const {
    return static_cast<double>(b - a) * 1000.0 / freq.QuadPart;
  }
};

// One timed request->reply cycle against the running worker. Returns ms, or <0.
double RoundTrip(SboxSession* session, BrokerMsgCtx* mctx, const Perf& perf,
                 const char* msg, size_t len) {
  ::ResetEvent(mctx->reply_event);
  mctx->replies = 0;
  const LONGLONG t0 = perf.now();
  if (sbox_broker_post_message(session, SBOX_MSG_STRING, msg, len) != 0)
    return -1.0;
  if (::WaitForSingleObject(mctx->reply_event, 15000) != WAIT_OBJECT_0 ||
      mctx->replies == 0)
    return -1.0;
  return perf.ms(t0, perf.now());
}

int RunBroker(const std::wstring& plugin_name) {
  printf("[sbox] role=broker pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();

  const std::wstring self = SelfPath();
  // The plugin (not sbox.exe) supplies the sandbox policy: load+verify it, run
  // configure(), and apply what it set. This keeps the container app-agnostic.
  PreparedSandbox sb;
  if (!PrepareSandbox(plugin_name, sb)) {
    printf("[sbox] broker: sandbox preparation failed\n");
    return 3;
  }

  BrokerMsgCtx mctx;
  mctx.reply_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);

  // Time the one-time spawn (process creation + sandbox lockdown setup to
  // resume). Spawns THIS image with --worker --plugin=<name> (appended inside
  // sbox_dll.cc from the policy's passthrough fields).
  Perf perf;
  const LONGLONG t_spawn0 = perf.now();
  SboxSession* session =
      sbox_broker_spawn(self.c_str(), &sb.policy, &OnBrokerReply, &mctx);
  const LONGLONG t_spawn1 = perf.now();
  if (!session) {
    printf("[sbox] broker: spawn failed\n");
    ::CloseHandle(mctx.reply_event);
    return 2;
  }

  const char msg[] = "ping from broker";
  // First (cold) round-trip also covers the worker's warmup + LowerToken +
  // reaching its run loop; the warm ones are steady-state broker<->worker RTT.
  const double first_rtt = RoundTrip(session, &mctx, perf, msg, sizeof(msg) - 1);
  const bool got_reply = first_rtt >= 0 && !mctx.unexpected;
  double warm_sum = 0;
  double warm_min = 0;
  int warm_n = 0;
  bool warm_ok = got_reply;
  for (int i = 0; i < 20 && warm_ok; ++i) {
    const double rtt = RoundTrip(session, &mctx, perf, msg, sizeof(msg) - 1);
    if (rtt < 0 || mctx.unexpected) {
      warm_ok = false;
      break;
    }
    warm_sum += rtt;
    if (warm_n == 0 || rtt < warm_min) warm_min = rtt;
    ++warm_n;
  }

  const int rc_close = sbox_broker_close(session);
  const int worker_exit = sbox_broker_wait(session);
  ::CloseHandle(mctx.reply_event);

  const double spawn_ms = perf.ms(t_spawn0, t_spawn1);
  const double warm_avg = warm_n ? warm_sum / warm_n : -1.0;
  printf("[sbox] spawn+lockdown=%.2f ms  first-roundtrip(cold)=%.3f ms"
         "  warm-roundtrip avg=%.3f min=%.3f ms (n=%d)\n",
         spawn_ms, first_rtt, warm_avg, warm_min, warm_n);

  const bool ok = got_reply && warm_ok && !mctx.unexpected && rc_close == 0 &&
                  worker_exit == kOk;
  printf("[sbox] broker: worker_exit=%d warm_rtts=%d -> %s\n", worker_exit,
         warm_n, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

// Named-pipe round-trip latency — models the new app->broker hop (the transport
// that used to be in-process on x64). Single process: a server thread echoes;
// the main thread times N round-trips. Isolates the pipe transport cost
// (cross-process scheduling is already in the warm broker<->worker number). No
// protocol, no auth — just RTT.
DWORD WINAPI PipeServerThread(void* arg) {
  const wchar_t* name = static_cast<const wchar_t*>(arg);
  HANDLE pipe = ::CreateNamedPipeW(
      name, PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0,
      nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return 1;
  if (!::ConnectNamedPipe(pipe, nullptr) &&
      ::GetLastError() != ERROR_PIPE_CONNECTED) {
    ::CloseHandle(pipe);
    return 2;
  }
  char buf[256];
  DWORD n = 0;
  while (::ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n > 0) {
    DWORD wrote = 0;
    if (!::WriteFile(pipe, buf, n, &wrote, nullptr)) break;
    if (n == 4 && std::memcmp(buf, "quit", 4) == 0) break;
  }
  ::FlushFileBuffers(pipe);
  ::DisconnectNamedPipe(pipe);
  ::CloseHandle(pipe);
  return 0;
}

int RunPipeBench() {
  printf("[sbox] role=pipe-bench pid=%lu\n", ::GetCurrentProcessId());
  const wchar_t* name = L"\\\\.\\pipe\\sbox_bench";
  HANDLE th = ::CreateThread(nullptr, 0, &PipeServerThread,
                             const_cast<wchar_t*>(name), 0, nullptr);
  if (!th) return 2;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  for (int i = 0; i < 200 && pipe == INVALID_HANDLE_VALUE; ++i) {
    pipe = ::CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) ::Sleep(1);
  }
  if (pipe == INVALID_HANDLE_VALUE) {
    ::WaitForSingleObject(th, 2000);
    ::CloseHandle(th);
    return 3;
  }
  DWORD mode = PIPE_READMODE_MESSAGE;
  ::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

  Perf perf;
  const char msg[] = "ping";
  char buf[256];
  DWORD w = 0, r = 0;
  ::WriteFile(pipe, msg, sizeof(msg) - 1, &w, nullptr);  // warm the pipe once
  ::ReadFile(pipe, buf, sizeof(buf), &r, nullptr);
  double sum = 0, mn = 0;
  int n = 0;
  for (int i = 0; i < 1000; ++i) {
    const LONGLONG t0 = perf.now();
    if (!::WriteFile(pipe, msg, sizeof(msg) - 1, &w, nullptr)) break;
    if (!::ReadFile(pipe, buf, sizeof(buf), &r, nullptr)) break;
    const double rtt = perf.ms(t0, perf.now());
    sum += rtt;
    if (n == 0 || rtt < mn) mn = rtt;
    ++n;
  }
  ::WriteFile(pipe, "quit", 4, &w, nullptr);
  ::ReadFile(pipe, buf, sizeof(buf), &r, nullptr);
  ::CloseHandle(pipe);
  ::WaitForSingleObject(th, 2000);
  ::CloseHandle(th);
  printf("[sbox] named-pipe RTT avg=%.4f min=%.4f ms (n=%d)\n",
         n ? sum / n : -1.0, mn, n);
  return n > 0 ? 0 : 1;
}

// ===== shared-broker rendezvous, fan-in, per-tenant worker, lifetime =====

// Per-user rendezvous point: a well-known, user-scoped pipe name.
std::wstring BrokerPipeName() {
  wchar_t user[256] = {};
  DWORD n = 256;
  const std::wstring u = ::GetUserNameW(user, &n) ? user : L"default";
  return L"\\\\.\\pipe\\sbox_broker_" + u;
}

std::atomic<int> g_active_clients{0};

// One connected client: read its request, spawn a DEDICATED sandbox worker, relay
// one round-trip, and reply with the broker + worker PIDs so the client can prove
// rendezvous fan-in (same broker) and per-tenant isolation (distinct workers).
struct ClientJob {
  HANDLE pipe;
  std::wstring self;
  const SboxPolicy* policy;  // the broker-service's plugin-prepared policy
};

DWORD WINAPI HandleClientThread(void* arg) {
  std::unique_ptr<ClientJob> job(static_cast<ClientJob*>(arg));
  HANDLE pipe = job->pipe;

  char req[256] = {};
  DWORD got = 0;
  std::string reply;
  if (::ReadFile(pipe, req, sizeof(req) - 1, &got, nullptr) && got > 0) {
    const SboxPolicy& policy = *job->policy;
    BrokerMsgCtx mctx;
    mctx.reply_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SboxSession* session = sbox_broker_spawn(job->self.c_str(), &policy,
                                             &OnBrokerReply, &mctx);
    if (session) {
      sbox_broker_post_message(session, SBOX_MSG_STRING, req, got);
      ::WaitForSingleObject(mctx.reply_event, 15000);
      sbox_broker_close(session);
      sbox_broker_wait(session);
      reply = "broker[pid=" + std::to_string(::GetCurrentProcessId()) + "] -> " +
              (mctx.last_reply.empty() ? std::string("(no worker reply)")
                                       : mctx.last_reply);
    } else {
      reply = "broker[pid=" + std::to_string(::GetCurrentProcessId()) +
              "] -> spawn FAILED";
    }
    ::CloseHandle(mctx.reply_event);
  } else {
    reply = "broker: empty request";
  }

  DWORD wrote = 0;
  ::WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &wrote,
              nullptr);
  ::FlushFileBuffers(pipe);
  ::DisconnectNamedPipe(pipe);
  ::CloseHandle(pipe);
  g_active_clients.fetch_sub(1);
  return 0;
}

// Long-lived broker: ONE per user. Race-free create-or-lose via
// FILE_FLAG_FIRST_PIPE_INSTANCE; serves many clients concurrently; idle-exits.
int RunBrokerService(const std::wstring& plugin_name) {
  printf("[sbox] role=broker-service pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();
  // Prepare the plugin-supplied policy ONCE; every client spawns a worker from
  // it. Intentionally leaked (process-lifetime singleton): client threads hold
  // &policy and may still run when this function returns on shutdown.
  auto* sb = new PreparedSandbox();
  if (!PrepareSandbox(plugin_name, *sb)) {
    printf("[sbox] broker-service: sandbox preparation failed\n");
    return 2;
  }
  const std::wstring self = SelfPath();
  const std::wstring name = BrokerPipeName();

  const DWORD kIdleMs = 3000;      // idle shutdown once no clients remain
  const DWORD kMaxLifeMs = 60000;  // hard safety cap
  const DWORD t_start = ::GetTickCount();
  bool first = true;
  int served = 0;

  for (;;) {
    HANDLE pipe = ::CreateNamedPipeW(
        name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
            (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      const DWORD e = ::GetLastError();
      if (first && e == ERROR_ACCESS_DENIED) {
        printf("[sbox] broker-service: pipe already owned -> lost race, "
               "exit 0\n");
        return 0;  // another broker won the rendezvous
      }
      printf("[sbox] broker-service: CreateNamedPipe failed: %lu\n", e);
      return 2;
    }
    if (first) {
      printf("[sbox] broker-service: WON rendezvous, listening (%ls)\n",
             name.c_str());
      first = false;
    }

    OVERLAPPED ov = {};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool have_client = false;
    if (::ConnectNamedPipe(pipe, &ov)) {
      have_client = true;
    } else {
      const DWORD e = ::GetLastError();
      if (e == ERROR_PIPE_CONNECTED) {
        have_client = true;
      } else if (e == ERROR_IO_PENDING) {
        if (::WaitForSingleObject(ov.hEvent, kIdleMs) == WAIT_OBJECT_0) {
          DWORD xfer = 0;
          have_client = ::GetOverlappedResult(pipe, &ov, &xfer, FALSE);
        } else {
          ::CancelIo(pipe);
        }
      }
    }
    ::CloseHandle(ov.hEvent);

    if (have_client) {
      ++served;
      g_active_clients.fetch_add(1);
      auto* job = new ClientJob{pipe, self, &sb->policy};
      HANDLE th = ::CreateThread(nullptr, 0, &HandleClientThread, job, 0, nullptr);
      if (th) {
        ::CloseHandle(th);
      } else {
        g_active_clients.fetch_sub(1);
        delete job;
        ::CloseHandle(pipe);
      }
    } else {
      ::CloseHandle(pipe);  // idle instance
      if (g_active_clients.load() == 0) {
        printf("[sbox] broker-service: idle %lums, no clients -> shutdown "
               "(served=%d)\n", kIdleMs, served);
        return 0;
      }
    }
    if (::GetTickCount() - t_start > kMaxLifeMs) {
      printf("[sbox] broker-service: max lifetime -> exit (served=%d)\n",
             served);
      return 0;
    }
  }
}

// Client: connect to the per-user broker, launching one if absent (the launched
// broker then wins-or-loses the create race). One request -> one response.
int RunClient(const std::wstring& plugin_name) {
  printf("[sbox] role=client pid=%lu\n", ::GetCurrentProcessId());
  const std::wstring name = BrokerPipeName();
  const std::wstring self = SelfPath();

  HANDLE pipe = INVALID_HANDLE_VALUE;
  bool launched = false;
  const DWORD deadline = ::GetTickCount() + 10000;
  for (;;) {
    pipe = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
    if (pipe != INVALID_HANDLE_VALUE) break;
    const DWORD e = ::GetLastError();
    if (e == ERROR_PIPE_BUSY) {
      ::WaitNamedPipeW(name.c_str(), 2000);
    } else if (e == ERROR_FILE_NOT_FOUND) {
      if (!launched) {
        std::wstring cmd =
            L"\"" + self + L"\" --broker-service --plugin " + plugin_name;
        STARTUPINFOW si = {sizeof(si)};
        PROCESS_INFORMATION pi = {};
        if (::CreateProcessW(self.c_str(), &cmd[0], nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
          ::CloseHandle(pi.hProcess);
          ::CloseHandle(pi.hThread);
        }
        launched = true;
      }
      ::Sleep(50);
    } else {
      printf("[sbox] client %lu: connect failed: %lu\n",
             ::GetCurrentProcessId(), e);
      return 2;
    }
    if (::GetTickCount() > deadline) {
      printf("[sbox] client %lu: broker unavailable\n",
             ::GetCurrentProcessId());
      return 2;
    }
  }

  DWORD mode = PIPE_READMODE_MESSAGE;
  ::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
  const std::string req =
      "ping from client " + std::to_string(::GetCurrentProcessId());
  DWORD wrote = 0, got = 0;
  char resp[512] = {};
  ::WriteFile(pipe, req.data(), static_cast<DWORD>(req.size()), &wrote, nullptr);
  const bool ok =
      ::ReadFile(pipe, resp, sizeof(resp) - 1, &got, nullptr) && got > 0;
  ::CloseHandle(pipe);
  if (!ok) {
    printf("[sbox] client %lu: no response\n", ::GetCurrentProcessId());
    return 1;
  }
  printf("[sbox] client %lu got: %.*s\n", ::GetCurrentProcessId(),
         static_cast<int>(got), resp);
  return 0;
}

// Role dispatch. Kept deliberately dumb and FIRST so neither persona can fall
// through into the other's init.
enum class Role {
  kNone,
  kBroker,
  kWorker,
  kPipeBench,
  kBrokerService,
  kClient
};

Role ParseRole(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--worker") == 0) return Role::kWorker;
    if (std::strcmp(argv[i], "--broker") == 0) return Role::kBroker;
    if (std::strcmp(argv[i], "--pipe-bench") == 0) return Role::kPipeBench;
    if (std::strcmp(argv[i], "--broker-service") == 0)
      return Role::kBrokerService;
    if (std::strcmp(argv[i], "--client") == 0) return Role::kClient;
  }
  return Role::kNone;
}

}  // namespace

int main(int argc, char** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  const Role role = ParseRole(argc, argv);
  const std::wstring plugin = ParsePluginName(argc, argv);

  // The broker/worker/rendezvous roles are all driven by a plugin; require its
  // name up front (the container is app-agnostic and has no built-in default).
  const bool needs_plugin = role == Role::kBroker || role == Role::kWorker ||
                            role == Role::kBrokerService ||
                            role == Role::kClient;
  if (needs_plugin && plugin.empty()) {
    printf("[sbox] this role requires --plugin <filename>\n");
    return 2;
  }

  switch (role) {
    case Role::kBroker:
      return RunBroker(plugin);
    case Role::kWorker:
      return RunWorker(plugin);
    case Role::kPipeBench:
      return RunPipeBench();
    case Role::kBrokerService:
      return RunBrokerService(plugin);
    case Role::kClient:
      return RunClient(plugin);
    case Role::kNone:
    default:
      printf("Usage: sbox.exe --broker|--worker|--broker-service|--client "
             "--plugin <filename> | --pipe-bench\n");
      return 2;
  }
}
