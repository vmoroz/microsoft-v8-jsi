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
// shutdown is called once after any warmup attempt, even without run,
// and must tolerate warmup failure.
// Any codegen/patching the plugin needs MUST happen in warmup; run is post-ACG.
#ifndef SBOX_H_
#define SBOX_H_

#include <stddef.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#include "sbox_stela.h"

// Pin the calling convention NOW (Node-API's NAPI_CDECL lesson): every export
// AND every function pointer is SBOX_CDECL, so a plugin built with a different
// toolchain still agrees on the ABI. You cannot pass function pointers across a
// DLL boundary without a fixed convention.
#ifndef SBOX_CDECL
#ifdef _WIN32
#define SBOX_CDECL __cdecl
#else
#define SBOX_CDECL
#endif
#endif

// Defined by the plugin DLL's build to export sbox_plugin_main; empty for the
// host EXE (which only CALLS the resolved pointer, never exports it).
#ifndef SBOX_API
#ifdef SBOX_IMPL
#ifdef _WIN32
#define SBOX_API __declspec(dllexport)
#else
#define SBOX_API __attribute__((visibility("default")))
#endif
#else
#define SBOX_API
#endif
#endif

#define SBOX_ABI_VERSION 5u

#ifdef __cplusplus
extern "C" {
#endif

// A UTF-16 code unit. Every string in this ABI is NUL-terminated UTF-16.
#ifdef __cplusplus
typedef char16_t sbox_char16;
#else
typedef uint16_t sbox_char16;
#endif

// Opaque, typed handles (Node-API style — never void*).
typedef struct sbox_config_s* sbox_config;  // broker: the policy builder
typedef struct sbox_worker_s* sbox_worker;  // worker: the run context
typedef struct sbox_broker_s* sbox_broker;
typedef struct sbox_broker_worker_s* sbox_broker_worker;

/**
 * Result codes. 0 is success; errors are grouped into bands by failure class,
 * so a consumer can map an unknown code to its band (status & 0xF000):
 * 0x1000 caller contract, 0x7000 the operation failed.
 */
SBOX_ENUM(int32_t, sbox_status){
    sbox_status_ok = 0,
    sbox_status_invalid_arg = 0x1001,      ///< bad argument, or a rejected setter
    sbox_status_version_mismatch = 0x1002, ///< the host and plugin ABI versions differ
    /// The operation failed. From sbox_broker_api.post_message it means nothing
    /// was written.
    sbox_status_failed = 0x7001,
};

/**
 * Message kinds on the duplex worker channel. string and binary are the
 * engine's opaque guest frames. lifecycle is container- or host-emitted and
 * plugin-forbidden (the worker-api post_message rejects it), so a readiness
 * marker can never be forged by the engine or a guest. The values are on the
 * wire.
 */
SBOX_ENUM(int32_t, sbox_msg_kind){
    sbox_msg_kind_string = 0,
    sbox_msg_kind_binary = 1,
    sbox_msg_kind_lifecycle = 2,
};

/**
 * Lifecycle payload: exactly four bytes, a little-endian u32 phase. startup and
 * security are container observations; exit is broker-origin only. Unknown
 * phases are never delivered. The values are on the wire.
 */
SBOX_ENUM(int32_t, sbox_lifecycle_phase){
    sbox_lifecycle_phase_startup = 1,
    sbox_lifecycle_phase_security = 2,
    sbox_lifecycle_phase_exit = 3,
};

/** How the broker was started; see sbox_broker_start.mode. */
SBOX_ENUM(int32_t, sbox_broker_mode){
    sbox_broker_mode_dedicated = 0,
    sbox_broker_mode_shared = 1,
};

/**
 * Mandatory integrity levels for set_integrity. Mirrors the OS integrity the
 * container applies; the host maps these 1:1 to its internal enum.
 */
SBOX_ENUM(int32_t, sbox_integrity_level){
    sbox_integrity_level_low = 0,
    sbox_integrity_level_untrusted = 1,
};

/**
 * Restricted-token levels for set_tokens: the worker's initial token and its
 * lowered lockdown token (ordinary non-AppContainer mode). The host maps these
 * 1:1 to its internal enum (static_assert'd in sbox_config.cc).
 */
SBOX_ENUM(int32_t, sbox_token_level){
    sbox_token_level_lockdown = 0,               ///< null SID only; most restrictive
    sbox_token_level_limited = 1,                ///< restricting SIDs
    sbox_token_level_interactive = 2,            ///< plus Owner
    sbox_token_level_restricted_non_admin = 3,   ///< keeps user/authenticated SIDs
    sbox_token_level_restricted_same_access = 4, ///< all SIDs; least restrictive
};

typedef void(SBOX_CDECL* sbox_message_cb)(void* user_data,
                                          sbox_msg_kind kind,
                                          const void* data,
                                          size_t size);

// Host-owned identity storage borrowed only for broker_run. The opaque tokens
// are never serialized and must not be closed by the plugin.
typedef struct sbox_broker_start {
  uint32_t struct_size;
  sbox_broker_mode mode;
  const sbox_char16* endpoint_name;
  uint16_t native_machine;
  uint16_t reserved;
  const uint8_t* container_sha256;
  const uint8_t* plugin_sha256;
  const sbox_char16* container_final_path;
  const sbox_char16* plugin_final_path;
  const void* container_file_token;
  const void* plugin_file_token;
  const uint8_t* dedicated_nonce;
  size_t dedicated_nonce_size;
} sbox_broker_start;
#define SBOX_BROKER_START_INIT                                              \
  {sizeof(sbox_broker_start), sbox_broker_mode_dedicated, NULL, 0, 0, NULL, \
   NULL, NULL, NULL, NULL, NULL, NULL, 0}

// configure_and_spawn copies configure_data before the call returns. Message
// buffers are borrowed only for callback duration. After a successful spawn,
// the plugin owns the worker: close is called at most once and wait exactly
// once. wait is destructive and invalidates the handle; callbacks have stopped
// when it returns. EXIT arrives at most once, after all queued worker output,
// but may be absent once close/wait starts. It carries no exit code, does not
// replace the single wait, and is not permission to free handles or context.
// Callbacks must return promptly and never block or call close/wait;
// wait gives the reader 5 s to join; a callback still running after that
// budget is unsupported.
// The host owns this table and every opaque host token.
typedef struct sbox_broker_api {
  uint32_t struct_size;
  sbox_status(SBOX_CDECL* configure_and_spawn)(
      sbox_broker broker,
      const void* configure_data,
      size_t configure_data_size,
      sbox_message_cb on_message,
      void* user_data,
      sbox_broker_worker* out_worker);
  sbox_status(SBOX_CDECL* post_message)(sbox_broker_worker worker,
                                        sbox_msg_kind kind,
                                        const void* data,
                                        size_t size);
  sbox_status(SBOX_CDECL* close)(sbox_broker_worker worker);
  sbox_status(SBOX_CDECL* wait)(sbox_broker_worker worker,
                                int32_t* out_exit_code);
} sbox_broker_api;
#define SBOX_BROKER_API_INIT {sizeof(sbox_broker_api), NULL, NULL, NULL, NULL}

// --- sbox.exe -> plugin, BROKER role: services configure() uses to describe
// the sandbox. sbox speaks ACG (a mitigation), never JIT. Every setter returns
// sbox_status; a rejected setter poisons the builder so a partial/invalid config
// can never spawn (fail closed). Limits: <=64 file rules, <=64 capabilities,
// <=4096 plugin-data bytes. ---
typedef struct sbox_config_api {
  uint32_t struct_size;  // sizeof(sbox_config_api); lets the plugin version-check
  // Arbitrary Code Guard.
  sbox_status(SBOX_CDECL* set_acg)(sbox_config config, bool enabled);
  sbox_status(SBOX_CDECL* set_integrity)(sbox_config config,
                                         sbox_integrity_level initial,
                                         sbox_integrity_level delayed);
  sbox_status(SBOX_CDECL* add_file_rule)(sbox_config config,
                                         const sbox_char16* pattern,
                                         bool readonly);
  sbox_status(SBOX_CDECL* add_capability)(sbox_config config,
                                          const sbox_char16* capability_sid);
  sbox_status(SBOX_CDECL* set_app_container)(sbox_config config,
                                             bool enabled,
                                             bool lpac,
                                             const sbox_char16* profile);
  // DLLs the worker will LoadLibrary pre-lockdown. sbox verifies each (app-dir
  // filename only, Authenticode). The plugin DLL itself is implicit.
  sbox_status(SBOX_CDECL* allow_engine_dll)(sbox_config config,
                                            const sbox_char16* filename);
  // Opaque app-knowledge blob carried broker->worker; sbox NEVER interprets it.
  // The plugin encodes its own run profile here (e.g. jitless engine choice,
  // snapshot path) and reads it back in warmup via sbox_worker_api.get_plugin_data.
  sbox_status(SBOX_CDECL* set_plugin_data)(sbox_config config,
                                           const void* data,
                                           size_t size);
  // Restricted-token levels for ordinary (non-AppContainer) mode: the worker's
  // initial token and the lowered lockdown token. Appended last to keep the
  // vtable append-only across the ABI bump.
  sbox_status(SBOX_CDECL* set_tokens)(sbox_config config,
                                      sbox_token_level initial_token,
                                      sbox_token_level lockdown_token);
} sbox_config_api;
#define SBOX_CONFIG_API_INIT \
  {sizeof(sbox_config_api), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}

// --- sbox.exe -> plugin, WORKER role: services warmup()/run() use. ---
typedef struct sbox_worker_api {
  uint32_t struct_size;  // sizeof(sbox_worker_api)
  // the broker-set opaque blob (app knowledge); valid for the worker lifetime.
  sbox_status(SBOX_CDECL* get_plugin_data)(sbox_worker worker,
                                           const void** out_data,
                                           size_t* out_size);
  // true if ACG is/will be armed.
  bool(SBOX_CDECL* acg_enabled)(sbox_worker worker);
  // WebView2-style duplex message channel (opaque frames; host-untrusted input).
  sbox_status(SBOX_CDECL* post_message)(sbox_worker worker,
                                        sbox_msg_kind kind,
                                        const void* data,
                                        size_t size);
  // HANDLE to wait on.
  void*(SBOX_CDECL* inbound_event)(sbox_worker worker);
  sbox_status(SBOX_CDECL* drain_messages)(sbox_worker worker,
                                          sbox_message_cb on_message,
                                          void* user_data);
  // HANDLE: host asked to close.
  void*(SBOX_CDECL* close_event)(sbox_worker worker);
} sbox_worker_api;
#define SBOX_WORKER_API_INIT \
  {sizeof(sbox_worker_api), NULL, NULL, NULL, NULL, NULL, NULL}

// --- the plugin interface (plugin implements; sbox.exe calls by role) ---
typedef struct sbox_plugin_api {
  uint32_t struct_size;  // sizeof(sbox_plugin_api)
  uint32_t abi_version;  // == SBOX_ABI_VERSION the plugin was built against
  // BROKER: describe the sandbox the worker will run in.
  // configure_data is copied host storage valid only for this call.
  sbox_status(SBOX_CDECL* configure)(sbox_config config,
                                     const sbox_config_api* api,
                                     const void* configure_data,
                                     size_t configure_data_size);
  // Blocking coordinator entry. It must stop accepts and join every task and
  // broker worker before returning.
  sbox_status(SBOX_CDECL* broker_run)(sbox_broker broker,
                                      const sbox_broker_api* api,
                                      const sbox_broker_start* start);
  // WORKER (driven in order by sbox.exe):
  // PRE-lockdown.
  sbox_status(SBOX_CDECL* warmup)(sbox_worker worker,
                                  const sbox_worker_api* api);
  //              --- sbox.exe lowers the token here (ACG armed) ---
  // POST-lockdown.
  sbox_status(SBOX_CDECL* run)(sbox_worker worker, const sbox_worker_api* api);
  void(SBOX_CDECL* shutdown)(sbox_worker worker);
} sbox_plugin_api;
#define SBOX_PLUGIN_API_INIT \
  {sizeof(sbox_plugin_api), 0, NULL, NULL, NULL, NULL, NULL}

// The plugin's single required export (cf. Node-API napi_register_module_v1).
// sbox.exe resolves it by name from the --plugin DLL — no import lib, so the
// host EXE can be renamed. Both sides version-check host_abi_version vs
// SBOX_ABI_VERSION. The returned sbox_plugin_api is owned by the plugin (typically a
// file-scope static) and must outlive every call sbox.exe makes through it.
#define SBOX_PLUGIN_ENTRY "sbox_plugin_main"
typedef sbox_status(SBOX_CDECL* sbox_plugin_main_fn)(
    uint32_t host_abi_version,
    const sbox_plugin_api** out_plugin);
SBOX_API sbox_status SBOX_CDECL
sbox_plugin_main(uint32_t host_abi_version, const sbox_plugin_api** out_plugin);

#ifdef __cplusplus
}
#endif
#endif  // SBOX_H_
