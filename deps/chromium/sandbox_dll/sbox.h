// sbox.h — the sbox.exe plugin ABI. The host EXE is a generic, renameable
// sandbox container; a plugin DLL (e.g. v8host.dll) carries ALL app knowledge.
// Plugin authors include ONLY this header; they never link or import the host
// EXE by name (that would pin its name) and never touch the sandbox core
// (sbox_core_internal.h). Host services are passed IN as function-pointer
// structs; the plugin exposes exactly one resolved-by-name export.
//
// EXPERIMENTAL / not yet ABI-frozen.
//
// Lifecycle, driven by sbox.exe (the ACG-correct ordering IS the contract):
//   broker:  resolve+verify plugin -> configure(cfg, config_api)
//                                   -> sbox applies the policy -> spawn worker
//   worker:  resolve+verify plugin -> warmup(w, worker_api)   (PRE-lockdown)
//                                   -> sbox lowers the token   (ACG armed here)
//                                   -> run(w, worker_api)      (POST-lockdown)
//                                   -> shutdown(w)
// shutdown is called once after any warmup attempt and must tolerate failure.
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

#define SBOX_ABI_VERSION 5u

// Opaque, typed handles (Node-API style — never void*).
typedef struct sbox_config_s* sbox_config;  // broker: the policy builder
typedef struct sbox_worker_s* sbox_worker;  // worker: the run context
typedef struct sbox_broker_s* sbox_broker;
typedef struct sbox_broker_worker_s* sbox_broker_worker;

typedef enum {
  sbox_ok = 0,
  sbox_error = 1,
  sbox_error_version = 2,
  sbox_error_args = 3,
} sbox_status;

// Message kinds on the duplex worker channel. string/binary are the engine's
// opaque guest frames; sbox_msg_lifecycle is container- or host-emitted and
// plugin-FORBIDDEN (the worker-api post_message rejects it), so a
// readiness marker can never be forged by the engine or a guest.
typedef enum {
  sbox_msg_string = 0,
  sbox_msg_binary = 1,
  sbox_msg_lifecycle = 2,
} sbox_msg_kind;

// Lifecycle payload: exactly four bytes, a little-endian u32 phase.
// STARTUP/SECURITY are container observations; EXIT is broker-origin only.
// Unknown phases are never delivered.
typedef enum sbox_lifecycle_phase {
  SBOX_LIFECYCLE_STARTUP = 1,
  SBOX_LIFECYCLE_SECURITY = 2,
  SBOX_LIFECYCLE_EXIT = 3,
} sbox_lifecycle_phase;

typedef enum {
  sbox_broker_mode_dedicated = 0,
  sbox_broker_mode_shared = 1,
} sbox_broker_mode;

// Mandatory integrity levels for set_integrity(initial, delayed). Mirrors the OS
// integrity the container applies; the host maps these 1:1 to its internal enum.
typedef enum {
  sbox_integrity_low = 0,
  sbox_integrity_untrusted = 1,
} sbox_integrity_level;

// Restricted-token levels for set_tokens: the worker's initial token and its
// lowered lockdown token (ordinary non-AppContainer mode). The host maps these
// 1:1 to its internal enum (static_assert'd in sbox_config.cc).
typedef enum {
  sbox_token_lockdown = 0,                // null SID only; most restrictive
  sbox_token_limited = 1,                 // restricting SIDs
  sbox_token_interactive = 2,             // + Owner
  sbox_token_restricted_non_admin = 3,    // keeps user/authenticated SIDs
  sbox_token_restricted_same_access = 4,  // all SIDs (~ caller access); least restrictive
} sbox_token_level;

typedef void(SBOX_CALL* sbox_message_cb)(void* ctx, sbox_msg_kind kind,
                                         const void* data, size_t len);

// Host-owned identity storage borrowed only for broker_run. The opaque tokens
// are never serialized and must not be closed by the plugin.
typedef struct sbox_broker_start {
  uint32_t struct_size;
  uint32_t mode;
  const wchar_t* endpoint_name;
  uint16_t native_machine;
  uint16_t reserved;
  const uint8_t* container_sha256;
  const uint8_t* plugin_sha256;
  const wchar_t* container_final_path;
  const wchar_t* plugin_final_path;
  const void* container_file_token;
  const void* plugin_file_token;
  const uint8_t* dedicated_nonce;
  size_t dedicated_nonce_size;
} sbox_broker_start;

// configure_and_spawn copies configure_data before the call returns. Message
// buffers are borrowed only for callback duration. After a successful spawn,
// the plugin owns the worker: close is called at most once and wait exactly
// once. wait is destructive and invalidates the handle; callbacks have stopped
// when it returns. EXIT arrives at most once, after all queued worker output,
// but may be absent once close/wait starts. It carries no exit code, does not
// replace the single wait, and is not permission to free handles or context.
// The callback must not call close/wait.
// The host owns this table and every opaque host token.
typedef struct sbox_broker_api {
  uint32_t struct_size;
  sbox_status(SBOX_CALL* configure_and_spawn)(
      sbox_broker broker,
      const void* configure_data,
      size_t configure_data_size,
      sbox_message_cb on_message,
      void* callback_context,
      sbox_broker_worker* out_worker);
  sbox_status(SBOX_CALL* post_message)(sbox_broker_worker worker,
                                       sbox_msg_kind kind,
                                       const void* data,
                                       size_t size);
  sbox_status(SBOX_CALL* close)(sbox_broker_worker worker);
  sbox_status(SBOX_CALL* wait)(sbox_broker_worker worker,
                               int32_t* out_exit_code);
} sbox_broker_api;

// --- sbox.exe -> plugin, BROKER role: services configure() uses to describe
// the sandbox. sbox speaks ACG (a mitigation), never JIT. Every setter returns
// sbox_status; a rejected setter poisons the builder so a partial/invalid config
// can never spawn (fail closed). Limits: <=64 file rules, <=64 capabilities,
// <=4096 plugin-data bytes. ---
typedef struct sbox_config_api {
  uint32_t struct_size;  // sizeof(sbox_config_api); lets the plugin version-check
  sbox_status (SBOX_CALL* set_acg)(sbox_config, int enable);  // Arbitrary Code Guard
  sbox_status (SBOX_CALL* set_integrity)(sbox_config, int initial, int delayed);
  sbox_status (SBOX_CALL* add_file_rule)(sbox_config, const wchar_t* pattern,
                                         int readonly);
  sbox_status (SBOX_CALL* add_capability)(sbox_config,
                                          const wchar_t* capability_sid);
  sbox_status (SBOX_CALL* set_app_container)(sbox_config, int enable, int lpac,
                                             const wchar_t* profile);
  // DLLs the worker will LoadLibrary pre-lockdown. sbox verifies each (app-dir
  // filename only, Authenticode). The plugin DLL itself is implicit.
  sbox_status (SBOX_CALL* allow_engine_dll)(sbox_config, const wchar_t* filename);
  // Opaque app-knowledge blob carried broker->worker; sbox NEVER interprets it.
  // The plugin encodes its own run profile here (e.g. jitless engine choice,
  // snapshot path) and reads it back in warmup via sbox_worker_api.get_plugin_data.
  sbox_status (SBOX_CALL* set_plugin_data)(sbox_config, const void* data, size_t len);
  // Restricted-token levels (sbox_token_level) for ordinary (non-AppContainer)
  // mode: the worker's initial token and the lowered lockdown token. Appended
  // last to keep the vtable append-only across the ABI bump.
  sbox_status (SBOX_CALL* set_tokens)(sbox_config, int initial_token,
                                      int lockdown_token);
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
  // configure_data is copied host storage valid only for this call.
  sbox_status (SBOX_CALL* configure)(sbox_config cfg,
                                     const sbox_config_api* api,
                                     const void* configure_data,
                                     size_t configure_data_size);
  // Blocking coordinator entry. It must stop accepts and join every task and
  // broker worker before returning.
  sbox_status (SBOX_CALL* broker_run)(sbox_broker broker,
                                      const sbox_broker_api* api,
                                      const sbox_broker_start* start);
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
