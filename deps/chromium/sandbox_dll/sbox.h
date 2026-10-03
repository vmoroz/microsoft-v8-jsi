// sbox.h — the sbox.exe plugin ABI. The host EXE is a generic, renameable
// sandbox container; a plugin DLL (e.g. v8host.dll) carries ALL app knowledge.
// Plugin authors include ONLY this header; they never link or import the host
// EXE by name (that would pin its name) and never touch the sandbox core
// (sbox_core_internal.h). Host services are passed IN as function-pointer
// structs; the plugin exposes exactly one resolved-by-name export.
//
// EXPERIMENTAL / not yet ABI-frozen. First iteration — deliberately minimal.
// Formal ABI versioning/negotiation and the Node-API-grade safety pass are
// deferred; calling conventions and opaque-handle discipline go in NOW because
// they are correctness, not polish.
//
// Lifecycle, driven by sbox.exe (the ACG-correct ordering IS the contract):
//   broker:  resolve+verify plugin -> configure(cfg, config_api)
//                                   -> sbox applies the policy -> spawn worker
//   worker:  resolve+verify plugin -> warmup(w, worker_api)   (PRE-lockdown)
//                                   -> sbox lowers the token   (ACG armed here)
//                                   -> run(w, worker_api)      (POST-lockdown)
//                                   -> shutdown(w)
// Any codegen/patching the plugin needs MUST happen in warmup; run is post-ACG.
#ifndef SANDBOX_DLL_SBOX_H_
#define SANDBOX_DLL_SBOX_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pin the calling convention NOW (Node-API's NAPI_CDECL lesson): every export
// AND every function pointer is SBOX_CALL, so a plugin built with a different
// toolchain still agrees on the ABI. You cannot pass function pointers across a
// DLL boundary without a fixed convention.
#ifndef SBOX_CALL
#define SBOX_CALL __cdecl
#endif

// Defined by the plugin DLL's build to export sbox_plugin_main; empty for the
// host EXE (which only CALLS the resolved pointer, never exports it).
#ifdef SBOX_PLUGIN_IMPL
#define SBOX_EXPORT __declspec(dllexport)
#else
#define SBOX_EXPORT
#endif

#define SBOX_ABI_VERSION 1u

// Opaque, typed handles (Node-API style — never void*).
typedef struct sbox_config_s* sbox_config;  // broker: the policy builder
typedef struct sbox_worker_s* sbox_worker;  // worker: the run context

typedef enum {
  sbox_ok = 0,
  sbox_error = 1,
  sbox_error_version = 2,
  sbox_error_args = 3,
} sbox_status;

typedef enum { sbox_msg_string = 0, sbox_msg_binary = 1 } sbox_msg_kind;

// Mandatory integrity levels for set_integrity(initial, delayed). Mirrors the OS
// integrity the container applies; the host maps these 1:1 to its internal enum.
typedef enum {
  sbox_integrity_low = 0,
  sbox_integrity_untrusted = 1,
} sbox_integrity_level;

typedef void(SBOX_CALL* sbox_message_cb)(void* ctx, sbox_msg_kind kind,
                                         const void* data, size_t len);

// --- sbox.exe -> plugin, BROKER role: services configure() uses to describe
// the sandbox. sbox speaks ACG (a mitigation), never JIT. ---
typedef struct sbox_config_api {
  uint32_t struct_size;  // sizeof(sbox_config_api); lets the plugin version-check
  void (SBOX_CALL* set_acg)(sbox_config, int enable);  // Arbitrary Code Guard
  void (SBOX_CALL* set_integrity)(sbox_config, int initial, int delayed);
  sbox_status (SBOX_CALL* add_file_rule)(sbox_config, const wchar_t* pattern,
                                         int readonly);
  sbox_status (SBOX_CALL* add_capability)(sbox_config,
                                          const wchar_t* capability_sid);
  void (SBOX_CALL* set_app_container)(sbox_config, int enable, int lpac,
                                      const wchar_t* profile);
  // DLLs the worker will LoadLibrary pre-lockdown. sbox verifies each (app-dir
  // filename only, Authenticode). The plugin DLL itself is implicit.
  sbox_status (SBOX_CALL* allow_engine_dll)(sbox_config, const wchar_t* filename);
  // Opaque app-knowledge blob carried broker->worker; sbox NEVER interprets it.
  // The plugin encodes its own run profile here (e.g. jitless engine choice,
  // snapshot path) and reads it back in warmup via sbox_worker_api.get_plugin_data.
  void (SBOX_CALL* set_plugin_data)(sbox_config, const void* data, size_t len);
} sbox_config_api;

// --- sbox.exe -> plugin, WORKER role: services warmup()/run() use. ---
typedef struct sbox_worker_api {
  uint32_t struct_size;  // sizeof(sbox_worker_api)
  // the broker-set opaque blob (app knowledge); valid for the worker lifetime.
  sbox_status (SBOX_CALL* get_plugin_data)(sbox_worker, const void** data,
                                           size_t* len);
  int (SBOX_CALL* acg_enabled)(sbox_worker);  // 1 if ACG is/will be armed
  // WebView2-style duplex message channel (opaque frames; host-untrusted input).
  sbox_status (SBOX_CALL* post_message)(sbox_worker, sbox_msg_kind,
                                        const void* data, size_t len);
  void* (SBOX_CALL* inbound_event)(sbox_worker);  // HANDLE to wait on
  sbox_status (SBOX_CALL* drain_messages)(sbox_worker, sbox_message_cb,
                                          void* ctx);
  void* (SBOX_CALL* close_event)(sbox_worker);  // HANDLE: host asked to close
} sbox_worker_api;

// --- the plugin interface (plugin implements; sbox.exe calls by role) ---
typedef struct sbox_plugin {
  uint32_t struct_size;  // sizeof(sbox_plugin)
  uint32_t abi_version;  // == SBOX_ABI_VERSION the plugin was built against
  // BROKER: describe the sandbox the worker will run in.
  sbox_status (SBOX_CALL* configure)(sbox_config cfg, const sbox_config_api* api);
  // WORKER (driven in order by sbox.exe):
  sbox_status (SBOX_CALL* warmup)(sbox_worker w,
                                  const sbox_worker_api* api);  // PRE-lockdown
  //              --- sbox.exe lowers the token here (ACG armed) ---
  sbox_status (SBOX_CALL* run)(sbox_worker w,
                               const sbox_worker_api* api);  // POST-lockdown
  void (SBOX_CALL* shutdown)(sbox_worker w);
} sbox_plugin;

// The plugin's single required export (cf. Node-API napi_register_module_v1).
// sbox.exe resolves it by name from the --plugin DLL — no import lib, so the
// host EXE can be renamed. Both sides version-check host_abi_version vs
// SBOX_ABI_VERSION. The returned sbox_plugin is owned by the plugin (typically a
// file-scope static) and must outlive every call sbox.exe makes through it.
#define SBOX_PLUGIN_ENTRY "sbox_plugin_main"
typedef sbox_status(SBOX_CALL* sbox_plugin_main_fn)(uint32_t host_abi_version,
                                                    const sbox_plugin** out);
SBOX_EXPORT sbox_status SBOX_CALL sbox_plugin_main(uint32_t host_abi_version,
                                                   const sbox_plugin** out);

#ifdef __cplusplus
}
#endif
#endif  // SANDBOX_DLL_SBOX_H_
