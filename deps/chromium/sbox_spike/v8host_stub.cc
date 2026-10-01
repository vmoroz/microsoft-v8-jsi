// v8host.dll — THROWAWAY stub payload for the spike (spike-plan.md §3.2). It
// proves the sbox.exe <-> v8host.dll plugin ABI and the ACG warmup/run ordering
// WITHOUT V8: warmup allocates + loads a stub engine (pre-lockdown), run does
// the ACG probe + one message round-trip (post-lockdown). It links ONLY
// sbox_plugin_abi.h — never the sandbox core (control inversion from today,
// where the payload owns main()).
//
// Not product code: not signed, testonly, never in the product build group.

#define V8HOST_PLUGIN_IMPL
#include "sbox_plugin_abi.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <string>

namespace {

const SboxHostServices* g_host = nullptr;
void* g_warm_scratch = nullptr;  // reserved pre-lockdown, freed at shutdown
int g_inbound = 0;
int g_replies = 0;

// Directory of the hosting sbox.exe (where the engine DLLs are staged).
std::wstring HostDir() {
  wchar_t buf[MAX_PATH] = {};
  ::GetModuleFileNameW(nullptr, buf, MAX_PATH);  // the EXE, not this DLL
  std::wstring p(buf);
  const size_t s = p.find_last_of(L'\\');
  return s == std::wstring::npos ? std::wstring() : p.substr(0, s + 1);
}

// The ACG probe: under MITIGATION_DYNAMIC_CODE_DISABLE a PAGE_EXECUTE_READWRITE
// allocation is refused with ERROR_DYNAMIC_CODE_BLOCKED (1655). Reads kernel
// state directly — not a guest "ready" string.
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

void OnInbound(void* ctx, int kind, const void* data, size_t len) {
  (void)ctx;
  (void)kind;
  ++g_inbound;
  std::string reply = "v8host.dll echo: ";
  reply.append(static_cast<const char*>(data), len);
  if (g_host->post_message(g_host->target, SBOX_PLUGIN_MSG_STRING, reply.data(),
                           reply.size()) == 0) {
    ++g_replies;
  }
}

}  // namespace

// PRE-lockdown. The payload's heavy setup lives here because ACG forbids codegen
// afterward: prove executable allocation works NOW, reserve scratch for the run
// phase, and load a stub "engine" (stands in for v8jsisb.dll).
extern "C" __declspec(dllexport) int v8host_worker_warmup(
    const SboxHostServices* host) {
  if (!host || host->struct_size < sizeof(SboxHostServices)) return 1;
  g_host = host;

  DWORD err = ERROR_SUCCESS;
  const bool exec_pre = CanAllocExecutable(&err);
  g_warm_scratch = ::VirtualAlloc(nullptr, 64 * 1024, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
  // Stub engine load: a benign System32 DLL stands in for v8jsisb.dll. Loaded
  // pre-lockdown because the lowered token can no longer open arbitrary files.
  HMODULE engine = ::LoadLibraryExW(L"winmm.dll", nullptr,
                                    LOAD_LIBRARY_SEARCH_SYSTEM32);
  printf("[v8host.dll] warmup: exec-alloc(pre)=%s scratch=%s stub-engine=%s\n",
         exec_pre ? "ALLOWED (ACG off)" : "blocked",
         g_warm_scratch ? "OK" : "FAIL", engine ? "loaded" : "FAIL");

  // S8 (report-only, opt-in via SBOX_SPIKE_REAL_ENGINE): confirm the REAL engine
  // DLL loads and its JSI-ABI entry resolves under the control-inverted,
  // pre-lockdown worker. Opt-in so the default run keeps clean H4 numbers (the
  // real engine adds ~60 ms of one-time load). Non-fatal.
  if (::GetEnvironmentVariableW(L"SBOX_SPIKE_REAL_ENGINE", nullptr, 0) > 0) {
    const std::wstring real_path = HostDir() + L"v8jsisb.dll";
    HMODULE real = ::LoadLibraryExW(real_path.c_str(), nullptr,
                                    LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                        LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    const bool created = real && ::GetProcAddress(real, "v8_create_runtime");
    printf("[v8host.dll] warmup: real-engine(v8jsisb.dll)=%s v8_create_runtime=%s\n",
           real ? "loaded" : "absent", created ? "resolved" : "n/a");
  }

  return (exec_pre && g_warm_scratch && engine) ? 0 : 2;
}

// POST-lockdown. ACG MUST now be in force: prove it with a FAILED executable
// allocation (observable kernel state), then service one message round-trip
// through the host services.
extern "C" __declspec(dllexport) int v8host_worker_run(
    const SboxHostServices* host) {
  if (!host) return 1;

  DWORD err = ERROR_SUCCESS;
  const bool exec_post = CanAllocExecutable(&err);
  printf("[v8host.dll] run: exec-alloc(post)=%s (err=%lu)\n",
         exec_post ? "ALLOWED -> ACG NOT ENFORCED"
                   : "BLOCKED (ACG in force)",
         err);
  if (exec_post) return 3;  // dynamic code allowed post-lockdown -> H3 FAILURE

  HANDLE inbound = static_cast<HANDLE>(host->inbound_event(host->target));
  HANDLE close_evt = static_cast<HANDLE>(host->close_event(host->target));
  if (!inbound || !close_evt) return 4;
  HANDLE waits[2] = {inbound, close_evt};
  printf("[v8host.dll] run: entering message loop\n");
  for (;;) {
    DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    const bool closing = (w == WAIT_OBJECT_0 + 1);
    if (w == WAIT_OBJECT_0 || closing) {
      host->drain_messages(host->target, &OnInbound, nullptr);
    } else {
      printf("[v8host.dll] run: loop wait failed wait=%lu err=%lu\n", w,
             ::GetLastError());
      return 5;
    }
    if (closing) break;
  }
  printf("[v8host.dll] run: inbound=%d replies=%d\n", g_inbound, g_replies);
  return (g_inbound > 0 && g_replies > 0) ? 0 : 6;
}

extern "C" __declspec(dllexport) void v8host_worker_shutdown(void) {
  if (g_warm_scratch) {
    ::VirtualFree(g_warm_scratch, 0, MEM_RELEASE);
    g_warm_scratch = nullptr;
  }
  printf("[v8host.dll] shutdown\n");
}
