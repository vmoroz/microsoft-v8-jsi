// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* ===========================================================================
 * EXPERIMENTAL API - NOT YET ABI-STABLE
 *
 * This is the consumer-compiled client ABI for v8host.dll. A consuming app
 * compiles against this header, LoadLibrary's v8host.dll, and calls the
 * v8host_client_* entry points; no import library is required. Every entry
 * point and every function pointer uses a fixed calling convention
 * (V8HOST_CDECL) so a consumer built with a different toolchain still agrees on
 * the ABI. The client connects the app to a broker that hosts guest JavaScript
 * in a sandboxed worker and relays results back on the app thread.
 *
 * This API is experimental and subject to change. Although it is C-based, it is
 * NOT ABI-safe yet: function signatures, struct fields, and enum values may
 * change without notice while the API remains in experimental mode. Do not
 * depend on binary compatibility across builds. Once the API leaves
 * experimental mode it will become ABI-stable and this notice will be removed.
 * =========================================================================== */

#ifndef V8HOST_CLIENT_H_
#define V8HOST_CLIENT_H_

#include <stddef.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#include "v8host_stela.h"

// Every export and every function pointer uses V8HOST_CDECL, so a consumer
// built with a different toolchain still agrees on the calling convention.
#ifndef V8HOST_CDECL
#ifdef _WIN32
#define V8HOST_CDECL __cdecl
#else
#define V8HOST_CDECL
#endif
#endif

// v8host.dll's own build defines V8HOST_IMPL to export the entry points.
// Consumers bind by name via LoadLibrary + GetProcAddress (see the _fn
// typedefs), so by default the declarations carry no import decoration. A
// consumer that links an import library may predefine V8HOST_API as
// __declspec(dllimport).
#ifndef V8HOST_API
#ifdef V8HOST_IMPL
#ifdef _WIN32
#define V8HOST_API __declspec(dllexport)
#else
#define V8HOST_API __attribute__((visibility("default")))
#endif
#else
#define V8HOST_API
#endif
#endif

// The consumer passes the value it compiled against to v8host_initialize. The
// DLL serves older consumers and rejects newer ones. The end-to-end runtime
// contract is the broker wire version, negotiated separately.
#define V8HOST_ABI_VERSION 1u

// A string length meaning "the string is NUL-terminated".
#define V8HOST_AUTO_LENGTH SIZE_MAX

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
typedef char16_t v8host_char16;
#else
typedef uint16_t v8host_char16;
#endif

/** Broker mode. The values match the wire endpoint_mode numbering. */
V8HOST_ENUM(int32_t, v8host_broker_mode){
    v8host_broker_mode_dedicated = 0, ///< a broker owned by this session
    v8host_broker_mode_shared = 1,    ///< a broker shared across sessions
};

/** Security tier. */
V8HOST_ENUM(int32_t, v8host_tier){
    v8host_tier_untrusted = 0, ///< jitless plus ACG (default)
    v8host_tier_trusted = 1,   ///< JIT, ACG off
};

/** The worker's mandatory integrity level. The values are sbox's. */
V8HOST_ENUM(int32_t, v8host_integrity_level){
    v8host_integrity_level_low = 0,
    v8host_integrity_level_untrusted = 1,
};

/**
 * Restricted-token levels for ordinary (non-AppContainer) mode, from most to
 * least restrictive. The values are sbox's.
 */
V8HOST_ENUM(int32_t, v8host_token_level){
    v8host_token_level_lockdown = 0,               ///< null SID only
    v8host_token_level_limited = 1,                ///< restricting SIDs
    v8host_token_level_interactive = 2,            ///< plus Owner
    v8host_token_level_restricted_non_admin = 3,   ///< keeps user SIDs
    v8host_token_level_restricted_same_access = 4, ///< all SIDs
};

/** The kind of a relay message frame. */
V8HOST_ENUM(int32_t, v8host_message_kind){
    v8host_message_kind_string = 0, ///< a string frame
    v8host_message_kind_binary = 1, ///< a binary frame
};

/** Session states, reported through v8host_session_state_cb. */
V8HOST_ENUM(int32_t, v8host_session_state){
    v8host_session_state_creating = 0,
    v8host_session_state_ready = 1,
    v8host_session_state_worker_startup_ready = 2,
    v8host_session_state_worker_security_ready = 3,
    v8host_session_state_closed = 4,
};

/**
 * Run events, reported through v8host_run_event_cb. Every event except
 * started is terminal.
 */
V8HOST_ENUM(int32_t, v8host_run_event){
    v8host_run_event_started = 0,
    v8host_run_event_completed = 1,
    v8host_run_event_failed = 2,
    v8host_run_event_cancelled = 3,
    v8host_run_event_worker_exited = 4,
    v8host_run_event_broker_lost = 5,
};

/**
 * Result codes. 0 is success. Errors are grouped into bands by failure class,
 * so new codes can be added to a band without renumbering, and a consumer can
 * map an unknown code to its band (status & 0xF000):
 * - 0x1000: the caller's contract and quotas (fail-closed);
 * - 0x2000: lifecycle, state, and local resources;
 * - 0x3000: the broker transport and connection;
 * - 0x4000: asynchronous session and run terminal conditions;
 * - 0x7000: an unexpected internal failure.
 */
V8HOST_ENUM(int32_t, v8host_status){
    /// Success. For asynchronous calls, the inputs were validated and accepted.
    v8host_status_ok = 0,

    v8host_status_invalid_arg = 0x1001,         ///< NULL or invalid pointer, enum, length, or text
    v8host_status_invalid_struct_size = 0x1002, ///< struct_size is below the version 1 size
    v8host_status_version_mismatch = 0x1003,    ///< the consumer's ABI version is newer than the DLL's
    v8host_status_quota_exceeded = 0x1004,      ///< a documented cap was exceeded (for example 64)

    v8host_status_not_initialized = 0x2001, ///< called before v8host_initialize
    v8host_status_invalid_state = 0x2002,   ///< the handle is closed or invalid for the operation
    v8host_status_no_memory = 0x2003,       ///< a local allocation failed

    v8host_status_connect_failed = 0x3001, ///< rendezvous or connect-or-launch failed
    v8host_status_protocol_error = 0x3002, ///< malformed or unexpected wire traffic
    v8host_status_broker_lost = 0x3003,    ///< the broker transport dropped (terminal)

    v8host_status_run_terminal = 0x4001,          ///< post or cancel on an ended run
    v8host_status_callback_backpressure = 0x4002, ///< the app thread isn't draining callbacks
    /// A later run's tier, engine, or snapshot conflicts with the profile that
    /// the session's first run bound.
    v8host_status_profile_already_bound = 0x4003,

    v8host_status_internal_error = 0x7001, ///< an unexpected internal failure
};

// Opaque handles. A session owns all of its runs; there is no per-run release.
// Run handles live until v8host_session_close.
typedef struct v8host_session_s* v8host_session;
typedef struct v8host_run_s* v8host_run;

// Configuration builders (pull model). v8host_session_open and
// v8host_session_start_run create a builder, pass it to the consumer's
// configure callback, and free it when the callback returns; the handle never
// escapes the callback. A fresh builder holds the defaults. Every setter
// returns a status, and the first failure poisons the builder: later setters
// return that same status and change nothing, and the open or start_run call
// fails with it.
typedef struct v8host_config_s* v8host_config;
typedef struct v8host_run_config_s* v8host_run_config;

typedef v8host_status(V8HOST_CDECL* v8host_configure_session_cb)(
    void* user_data,
    v8host_config config);
typedef v8host_status(V8HOST_CDECL* v8host_configure_run_cb)(
    void* user_data,
    v8host_run_config config);

// Session configuration setters. String setters take a length in code units
// (bytes for _utf8, v8host_char16 units for _utf16), or V8HOST_AUTO_LENGTH for
// a NUL-terminated string. A NULL string, an embedded NUL, invalid UTF-8, or an
// unpaired surrogate returns v8host_status_invalid_arg.

// Default: v8host_broker_mode_dedicated.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_broker_mode(
    v8host_config config,
    v8host_broker_mode value);
// The session's default tier. Default: v8host_tier_untrusted.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_tier(
    v8host_config config,
    v8host_tier value);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_integrity_level(
    v8host_config config,
    v8host_integrity_level value);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_delayed_integrity_level(
    v8host_config config,
    v8host_integrity_level value);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_initial_token_level(
    v8host_config config,
    v8host_token_level value);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_lockdown_token_level(
    v8host_config config,
    v8host_token_level value);
// ACG. A trusted run requires this to be false. Default: false.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_prohibit_dynamic_code(
    v8host_config config,
    bool value);
// Adds a path pattern the worker may access. At most 64 rules
// (v8host_status_quota_exceeded beyond that).
V8HOST_API v8host_status V8HOST_CDECL v8host_config_add_file_rule_utf8(
    v8host_config config,
    const char* pattern,
    size_t length,
    bool readonly);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_add_file_rule_utf16(
    v8host_config config,
    const v8host_char16* pattern,
    size_t length,
    bool readonly);
// AppContainer requires a non-empty profile name. Default: false.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_use_app_container(
    v8host_config config,
    bool value);
// LPAC requires AppContainer. Default: false.
V8HOST_API v8host_status V8HOST_CDECL
v8host_config_set_low_privilege_app_container(v8host_config config, bool value);
// Required (non-empty) with AppContainer, and must stay empty without it.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_profile_name_utf8(
    v8host_config config,
    const char* value,
    size_t length);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_set_profile_name_utf16(
    v8host_config config,
    const v8host_char16* value,
    size_t length);
// Adds a non-empty capability SID. Permitted only with AppContainer. At most
// 64 capabilities.
V8HOST_API v8host_status V8HOST_CDECL v8host_config_add_capability_utf8(
    v8host_config config,
    const char* value,
    size_t length);
V8HOST_API v8host_status V8HOST_CDECL v8host_config_add_capability_utf16(
    v8host_config config,
    const v8host_char16* value,
    size_t length);

// Run configuration setters.

// Overrides the session tier for this run. It may not weaken the session
// envelope: a trusted run is rejected unless the session has ACG off.
V8HOST_API v8host_status V8HOST_CDECL v8host_run_config_set_tier(
    v8host_run_config config,
    v8host_tier value);
// A bare filename resolved within the worker's payload directory, never a
// path; the broker signature-verifies it. Unset: the tier default.
V8HOST_API v8host_status V8HOST_CDECL v8host_run_config_set_engine_dll_utf8(
    v8host_run_config config,
    const char* value,
    size_t length);
V8HOST_API v8host_status V8HOST_CDECL v8host_run_config_set_engine_dll_utf16(
    v8host_run_config config,
    const v8host_char16* value,
    size_t length);
// A non-empty payload-relative path, read before lockdown. Unset: none.
V8HOST_API v8host_status V8HOST_CDECL
v8host_run_config_set_startup_snapshot_path_utf8(v8host_run_config config,
                                                 const char* value,
                                                 size_t length);
V8HOST_API v8host_status V8HOST_CDECL
v8host_run_config_set_startup_snapshot_path_utf16(v8host_run_config config,
                                                  const v8host_char16* value,
                                                  size_t length);
// The guest script or bundle reference, copied. data is NULL iff size is 0.
V8HOST_API v8host_status V8HOST_CDECL v8host_run_config_set_payload(
    v8host_run_config config,
    const void* data,
    size_t size);

// Callback contract (design §9.1/§9.3): every callback is invoked on the app
// (callback) thread captured by the first successful v8host_initialize,
// never on an internal I/O thread, and never while an internal lock is held. Any
// buffer passed to a callback is owned by v8host and valid ONLY for the duration
// of that callback - copy it if you need to retain it; the client retains none
// of your pointers. Reentrant start/post/cancel/set_callbacks/close from inside
// a callback is supported.

// Session lifecycle transition or terminal error. `status` is v8host_status_ok
// for a benign transition, or a terminal error code when the session has failed
// (e.g. v8host_status_callback_backpressure, v8host_status_broker_lost).
typedef void(V8HOST_CDECL* v8host_session_state_cb)(
    void* user_data,
    v8host_session session,
    v8host_session_state state,
    v8host_status status);

// Run lifecycle event, including the single app-visible terminal event selected
// by the run-state arbiter. A terminal event carries the run's final `status`:
// v8host_status_ok on clean completion, else an error code (e.g.
// v8host_status_run_terminal on a post-terminal outcome,
// v8host_status_broker_lost on disconnect). A broker relay-cap overflow may end
// a run with failed / v8host_status_quota_exceeded. A per-connection overflow
// also closes the connection; its other live runs then end with broker_lost /
// v8host_status_broker_lost.
typedef void(V8HOST_CDECL* v8host_run_event_cb)(void* user_data,
                                                v8host_run run,
                                                v8host_run_event event,
                                                v8host_status status);

// Inbound relay frame from the worker for `run`. `data`/`size` are borrowed for
// the callback only.
typedef void(V8HOST_CDECL* v8host_relay_message_cb)(void* user_data,
                                                    v8host_run run,
                                                    v8host_message_kind kind,
                                                    const void* data,
                                                    size_t size);

// The broker transport dropped. Every live session and run on this connection is
// independently marked terminal with v8host_status_broker_lost through the
// session and run callbacks; the client does not replay prior requests.
typedef void(V8HOST_CDECL* v8host_broker_disconnect_cb)(void* user_data);

// Versioned callback table, installed per session via
// v8host_session_set_callbacks. The caller sets struct_size = sizeof(T); the
// DLL rejects a smaller table with v8host_status_invalid_struct_size and ignores
// unknown trailing fields. The table is copied on install and atomically
// replaces the prior table for FUTURE dispatch; already-queued events use the
// table snapshot captured when they were queued. Any member may be NULL to
// decline that notification.
typedef struct v8host_callbacks {
  uint32_t struct_size;  // = sizeof(v8host_callbacks)
  void* user_data;       // passed to every callback below
  v8host_session_state_cb on_session_state;
  v8host_run_event_cb on_run_event;
  v8host_relay_message_cb on_relay_message;
  v8host_broker_disconnect_cb on_broker_disconnect;
} v8host_callbacks;

#define V8HOST_CALLBACKS_INIT \
  { sizeof(v8host_callbacks), NULL, NULL, NULL, NULL, NULL }

// Process-idempotent and thread-safe. `abi_version` is the V8HOST_ABI_VERSION
// the consumer compiled against; a newer value (or 0) returns
// v8host_status_version_mismatch. The first successful call must occur on the
// consumer's callback/app thread, which must have a Windows message queue;
// that thread becomes the callback thread for the process.
V8HOST_API v8host_status V8HOST_CDECL v8host_initialize(uint32_t abi_version);

// Build and validate the session configuration through `configure` (NULL means
// all defaults), then begin connecting a session. A synchronous
// v8host_status_ok means the inputs were accepted, not that the session is
// connected; the outcome arrives via the session callback. On failure
// *out_session = NULL.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_open(
    v8host_configure_session_cb configure,
    void* user_data,
    v8host_session* out_session);

// Install (copy) the callback table for `session`, replacing any prior table.
// Status-returning so callers can observe a rejected table (bad struct_size,
// closed session, allocation failure) rather than install silently.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_set_callbacks(
    v8host_session session,
    const v8host_callbacks* callbacks);

// Build and validate the run configuration through `configure` (NULL means all
// defaults), then begin a run on `session`. A synchronous v8host_status_ok
// means the inputs were accepted; the run outcome arrives via the run callback.
// On failure *out_run = NULL.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_start_run(
    v8host_session session,
    v8host_configure_run_cb configure,
    void* user_data,
    v8host_run* out_run);

// Queue an outbound relay frame to the worker for `run`. `data`/`size` are
// copied before this call returns. A `kind` outside v8host_message_kind returns
// v8host_status_invalid_arg. A terminal run rejects with
// v8host_status_run_terminal. Transport admission may immediately return
// v8host_status_connect_failed, v8host_status_protocol_error, or
// v8host_status_quota_exceeded (nothing queued; the run continues).
V8HOST_API v8host_status V8HOST_CDECL v8host_run_post_message(
    v8host_run run,
    v8host_message_kind kind,
    const void* data,
    size_t size);

// Request cancellation of `run`. Success means the request was accepted, not
// that guest code had not already produced effects. A terminal run rejects with
// v8host_status_run_terminal. Transport admission may immediately return
// v8host_status_connect_failed, v8host_status_protocol_error, or
// v8host_status_quota_exceeded (nothing queued).
V8HOST_API v8host_status V8HOST_CDECL v8host_run_cancel(v8host_run run);

// Close `session` and invalidate all of its run handles. Nonblocking: it marks
// the session closed, suppresses queued callbacks, starts a best-effort close,
// and returns without waiting on broker I/O. Safe to call from within a
// callback. Always succeeds, so there is no status to report.
V8HOST_API void V8HOST_CDECL v8host_session_close(v8host_session session);

// Function-pointer types for GetProcAddress consumers.
typedef v8host_status(V8HOST_CDECL* v8host_initialize_fn)(uint32_t abi_version);
typedef v8host_status(V8HOST_CDECL* v8host_session_open_fn)(
    v8host_configure_session_cb configure,
    void* user_data,
    v8host_session* out_session);
typedef v8host_status(V8HOST_CDECL* v8host_session_set_callbacks_fn)(
    v8host_session session,
    const v8host_callbacks* callbacks);
typedef v8host_status(V8HOST_CDECL* v8host_session_start_run_fn)(
    v8host_session session,
    v8host_configure_run_cb configure,
    void* user_data,
    v8host_run* out_run);
typedef v8host_status(V8HOST_CDECL* v8host_run_post_message_fn)(
    v8host_run run,
    v8host_message_kind kind,
    const void* data,
    size_t size);
typedef v8host_status(V8HOST_CDECL* v8host_run_cancel_fn)(v8host_run run);
typedef void(V8HOST_CDECL* v8host_session_close_fn)(v8host_session session);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_broker_mode_fn)(
    v8host_config config,
    v8host_broker_mode value);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_tier_fn)(
    v8host_config config,
    v8host_tier value);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_integrity_level_fn)(
    v8host_config config,
    v8host_integrity_level value);
typedef v8host_status(
    V8HOST_CDECL* v8host_config_set_delayed_integrity_level_fn)(
    v8host_config config,
    v8host_integrity_level value);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_initial_token_level_fn)(
    v8host_config config,
    v8host_token_level value);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_lockdown_token_level_fn)(
    v8host_config config,
    v8host_token_level value);
typedef v8host_status(
    V8HOST_CDECL* v8host_config_set_prohibit_dynamic_code_fn)(
    v8host_config config,
    bool value);
typedef v8host_status(V8HOST_CDECL* v8host_config_add_file_rule_utf8_fn)(
    v8host_config config,
    const char* pattern,
    size_t length,
    bool readonly);
typedef v8host_status(V8HOST_CDECL* v8host_config_add_file_rule_utf16_fn)(
    v8host_config config,
    const v8host_char16* pattern,
    size_t length,
    bool readonly);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_use_app_container_fn)(
    v8host_config config,
    bool value);
typedef v8host_status(
    V8HOST_CDECL* v8host_config_set_low_privilege_app_container_fn)(
    v8host_config config,
    bool value);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_profile_name_utf8_fn)(
    v8host_config config,
    const char* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_config_set_profile_name_utf16_fn)(
    v8host_config config,
    const v8host_char16* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_config_add_capability_utf8_fn)(
    v8host_config config,
    const char* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_config_add_capability_utf16_fn)(
    v8host_config config,
    const v8host_char16* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_run_config_set_tier_fn)(
    v8host_run_config config,
    v8host_tier value);
typedef v8host_status(V8HOST_CDECL* v8host_run_config_set_engine_dll_utf8_fn)(
    v8host_run_config config,
    const char* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_run_config_set_engine_dll_utf16_fn)(
    v8host_run_config config,
    const v8host_char16* value,
    size_t length);
typedef v8host_status(
    V8HOST_CDECL* v8host_run_config_set_startup_snapshot_path_utf8_fn)(
    v8host_run_config config,
    const char* value,
    size_t length);
typedef v8host_status(
    V8HOST_CDECL* v8host_run_config_set_startup_snapshot_path_utf16_fn)(
    v8host_run_config config,
    const v8host_char16* value,
    size_t length);
typedef v8host_status(V8HOST_CDECL* v8host_run_config_set_payload_fn)(
    v8host_run_config config,
    const void* data,
    size_t size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // V8HOST_CLIENT_H_
