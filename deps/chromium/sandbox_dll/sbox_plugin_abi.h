// sbox_plugin_abi.h — the in-process contract between the V8-agnostic sbox.exe
// container and the v8host.dll engine payload it drives. Kept tiny and C-shaped
// so the payload DLL depends ONLY on this header — never on the sandbox core.
//
// EXPERIMENTAL / not yet ABI-frozen: this surface may still be reshaped. The
// shape below is the validated worker-direction lifecycle; the broker direction
// and a versioned error/config surface arrive with later work.
//
// Lifecycle (worker persona), driven by sbox.exe's worker main():
//   sbox_target_begin -> v8host_worker_warmup  (PRE-lockdown: load engine, codegen allowed)
//                     -> sbox_target_lower_token()
//                     -> v8host_worker_run      (POST-lockdown: ACG armed; message loop)
//                     -> v8host_worker_shutdown -> sbox_target_end
#ifndef SANDBOX_DLL_SBOX_PLUGIN_ABI_H_
#define SANDBOX_DLL_SBOX_PLUGIN_ABI_H_

#include <cstddef>
#include <cstdint>

// Mirrors sbox.h's SboxMsgKind, redeclared so the payload needs only this header.
#define SBOX_PLUGIN_MSG_STRING 0
#define SBOX_PLUGIN_MSG_BINARY 1

// Same shape as sbox.h's SboxMessageCb.
typedef void (*SboxPluginMessageCb)(void* ctx, int kind, const void* data,
                                    size_t len);

// sbox.exe -> v8host.dll: the host services the payload may call. The payload
// posts/drains through these pointers and never links sbox core.
typedef struct SboxHostServices {
  uint32_t struct_size;  // sizeof(SboxHostServices); lets the DLL version-check
  void* target;          // opaque SboxTarget*
  int (*post_message)(void* target, int kind, const void* data, size_t len);
  void* (*inbound_event)(void* target);
  int (*drain_messages)(void* target, SboxPluginMessageCb cb, void* ctx);
  void* (*close_event)(void* target);
} SboxHostServices;

// Worker-persona entrypoints exported by v8host.dll; sbox.exe resolves them by
// name via GetProcAddress (no import-lib link, so the DLL stays late-loaded).
typedef int (*v8host_worker_warmup_fn)(const SboxHostServices*);   // PRE-lockdown
typedef int (*v8host_worker_run_fn)(const SboxHostServices*);      // POST-lockdown
typedef void (*v8host_worker_shutdown_fn)(void);

#ifdef V8HOST_PLUGIN_IMPL
extern "C" __declspec(dllexport) int v8host_worker_warmup(
    const SboxHostServices*);
extern "C" __declspec(dllexport) int v8host_worker_run(const SboxHostServices*);
extern "C" __declspec(dllexport) void v8host_worker_shutdown(void);
#endif

#endif  // SANDBOX_DLL_SBOX_PLUGIN_ABI_H_
