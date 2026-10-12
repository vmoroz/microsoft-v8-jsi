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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint32_t, int32_t
#include <wchar.h>   // wchar_t (as a type in C)

#ifdef __cplusplus
extern "C" {
#endif

// Pin the calling convention NOW: every export AND every function pointer is
// V8HOST_CDECL, so a consumer built with a different toolchain still agrees on
// the ABI. You cannot pass function pointers across a DLL boundary without a
// fixed convention.
#ifndef V8HOST_CDECL
#define V8HOST_CDECL __cdecl
#endif

// v8host.dll's own build defines V8HOST_IMPL to export the
// v8host_client_* entry points. Consumers bind by name via LoadLibrary +
// GetProcAddress, so by default the declarations carry NO import decoration and
// need no import library. A consumer that prefers to link an import library
// instead may predefine V8HOST_API to __declspec(dllimport).
#ifndef V8HOST_API
#ifdef V8HOST_IMPL
#define V8HOST_API __declspec(dllexport)
#else
#define V8HOST_API
#endif
#endif

// Governs the in-proc call shape only (struct layouts + entry points). The
// effective end-to-end runtime contract is the broker wire version, negotiated
// separately; this value is struct_size-checked against the loaded DLL.
#define V8HOST_ABI_VERSION 1u

// Broker mode (matches the wire endpoint_mode numbering).
#define v8host_broker_mode_dedicated 0
#define v8host_broker_mode_shared    1

// Security tier.
#define v8host_tier_untrusted 0  // jitless + ACG (default)
#define v8host_tier_trusted   1  // JIT, ACG off

// Session-state codes (v8host_session_state_cb `state`).
#define v8host_session_state_creating               0
#define v8host_session_state_ready                  1
#define v8host_session_state_worker_startup_ready   2
#define v8host_session_state_worker_security_ready  3
#define v8host_session_state_closed                 4

// Run-event codes (v8host_run_event_cb `event`). All except STARTED are terminal.
#define v8host_run_event_started        0
#define v8host_run_event_completed      1
#define v8host_run_event_failed         2
#define v8host_run_event_cancelled      3
#define v8host_run_event_worker_exited  4
#define v8host_run_event_broker_lost    5

// Stable result codes. 0 is success; errors are grouped into stable bands by
// failure class so new codes can be added to a band without renumbering:
//   0x1000 - caller/argument contract and quotas (fail-closed)
//   0x2000 - lifecycle/state and local resources
//   0x3000 - broker transport / connection
//   0x4000 - asynchronous session/run terminal conditions
//   0x7000 - unexpected internal failure
// The enum is pinned to 32-bit int (see V8HOST_STATUS_FORCE_INT32), so these
// codes are ABI-compatible with a plain int return.
typedef enum v8host_status {
  v8host_status_ok = 0,  // success; for async calls, inputs were validated and accepted

  // 0x1000 - caller/argument contract and quotas (fail-closed).
  v8host_status_invalid_arg = 0x1001,  // NULL/invalid pointer, enum, or count/pair
  v8host_status_invalid_struct_size = 0x1002,  // struct_size < required v1 size
  v8host_status_version_mismatch     = 0x1003,  // client API / loaded-DLL ABI incompatible
  v8host_status_quota_exceeded       = 0x1004,  // a documented cap exceeded (e.g. 64/64)

  // 0x2000 - lifecycle/state and local resources.
  v8host_status_not_initialized = 0x2001,  // called before v8host_initialize
  v8host_status_invalid_state   = 0x2002,  // handle closed/invalid for the operation
  v8host_status_no_memory       = 0x2003,  // local allocation failed

  // 0x3000 - broker transport / connection.
  v8host_status_connect_failed     = 0x3001,  // rendezvous / connect-or-launch failed
  v8host_status_protocol_error    = 0x3002,  // malformed or unexpected wire traffic
  v8host_status_broker_lost = 0x3003,  // broker transport dropped (terminal)

  // 0x4000 - asynchronous session/run terminal conditions.
  v8host_status_run_terminal          = 0x4001,  // post/cancel on an ended run
  v8host_status_callback_backpressure = 0x4002,  // app thread not draining callbacks
  v8host_status_profile_already_bound = 0x4003,  // a later start_run's tier/engine/
                                            // snapshot conflicts with the
                                            // profile bound by the first run

  // 0x7000 - unexpected internal failure.
  v8host_status_internal_error = 0x7001,

  // Not a status value: pins the enum to 32-bit int for a stable ABI.
  V8HOST_STATUS_FORCE_INT32 = 0x7fffffff
} v8host_status;

// Versioning discipline for the input and callback structs below: a caller sets
// struct_size = sizeof(T) before passing a struct in. The DLL rejects a struct
// smaller than its required version-1 size with v8host_status_invalid_struct_size, and reads
// only the fields it knows while ignoring unknown trailing bytes on a larger
// struct. New fields are only ever appended. V8HostFileRule is a plain array
// element and is exempt (it carries no struct_size).

typedef struct V8HostFileRule {
  const wchar_t* pattern;  // path pattern the worker may access
  int32_t readonly;        // nonzero = read-only, zero = read-write
} V8HostFileRule;

// Stable per-session policy (the sandbox policy mirror + broker mode). Per-run
// overrides (tier/engine/snapshot) ride in V8HostRunInputs, not here.
typedef struct V8HostSessionConfig {
  uint32_t struct_size;  // = sizeof(V8HostSessionConfig)
  int32_t  broker_mode;  // v8host_broker_mode_dedicated | v8host_broker_mode_shared
  int32_t  tier;         // default tier: v8host_tier_untrusted | _TRUSTED
  int32_t  integrity;
  int32_t  delayed_integrity;
  int32_t  initial_token;
  int32_t  lockdown_token;
  int32_t  prohibit_dynamic_code;  // ACG; a trusted run requires this to be 0
  const V8HostFileRule* file_rules;
  size_t   file_rule_count;  // <= 64
  int32_t  use_app_container;
  int32_t  low_privilege_app_container;  // LPAC implies use_app_container != 0
  // Required (non-empty) when use_app_container != 0; must be empty/NULL when
  // AppContainer is off.
  const wchar_t* app_container_profile_name;
  // Permitted only when use_app_container != 0; must be empty when off.
  const wchar_t* const* capabilities;
  size_t capability_count;  // <= 64
} V8HostSessionConfig;

// Per-run inputs - the engine-facing overrides, delivered to the broker when a
// run starts.
typedef struct V8HostRunInputs {
  uint32_t struct_size;  // = sizeof(V8HostRunInputs)
  // -1 = use the session tier. May NOT weaken the session envelope: a trusted
  // (JIT) override is rejected unless the session has ACG off.
  int32_t tier_override;
  // NULL = tier default. A filename resolved within the worker's payload
  // directory only, never an arbitrary path; the broker signature-verifies it.
  const wchar_t* engine_dll_override;
  // NULL = none. A payload-relative path, read pre-lockdown from the payload dir.
  const wchar_t* startup_snapshot_path;
  const void* payload;  // the guest script / bundle reference
  size_t payload_len;
} V8HostRunInputs;

// Opaque handles. A v8host_session_s owns all of its v8host_run_s handles; there is no
// per-run release - run handles live until v8host_session_close.
typedef struct v8host_session_s v8host_session_s;
typedef struct v8host_run_s v8host_run_s;

// Callback contract (design §9.1/§9.3): every callback is invoked on the app
// (callback) thread captured by the first successful v8host_initialize,
// never on an internal I/O thread, and never while an internal lock is held. Any
// buffer passed to a callback is owned by v8host and valid ONLY for the duration
// of that callback - copy it if you need to retain it; the client retains none
// of your pointers. Reentrant start/post/cancel/set_callbacks/close from inside
// a callback is supported.

// Session lifecycle transition or terminal error. `state` is a session-state
// code (kept ABI-plain as int32_t). `status` is v8host_status_ok for a benign
// transition, or a terminal V8HOST_E_* code when the session has failed (e.g.
// v8host_status_callback_backpressure, v8host_status_broker_lost).
typedef void(V8HOST_CDECL* v8host_session_state_cb)(void* context,
                                                v8host_session_s* session,
                                                int32_t state,
                                                v8host_status status);

// Run lifecycle event, including the single app-visible terminal event selected
// by the run-state arbiter. `event` is a run-event code (ABI-plain int32_t). A
// terminal event carries the run's final `status`: v8host_status_ok on clean
// completion, else a V8HOST_E_* code (e.g. v8host_status_run_terminal on a
// post-terminal outcome, v8host_status_broker_lost on disconnect).
// A broker relay-cap overflow may end a run with FAILED / v8host_status_quota_exceeded.
// A per-connection overflow also closes the connection; its other live runs
// then end with BROKER_LOST / v8host_status_broker_lost.
typedef void(V8HOST_CDECL* v8host_run_event_cb)(void* context,
                                            v8host_run_s* run,
                                            int32_t event,
                                            v8host_status status);

// Inbound relay frame from the worker for `run`. `kind` is an app-defined
// message kind (ABI-plain int32_t). `data`/`len` are borrowed for the callback
// only.
typedef void(V8HOST_CDECL* v8host_relay_message_cb)(void* context,
                                                v8host_run_s* run,
                                                int32_t kind,
                                                const void* data,
                                                size_t len);

// The broker transport dropped. Every live session and run on this connection is
// independently marked terminal with v8host_status_broker_lost through the session
// and run callbacks; the client does not replay prior requests.
typedef void(V8HOST_CDECL* v8host_broker_disconnect_cb)(void* context);

// Versioned callback table, installed per session via
// v8host_session_set_callbacks. The table is copied on install and atomically
// replaces the prior table for FUTURE dispatch; already-queued events use the
// table snapshot captured when they were queued. Any member may be NULL to
// decline that notification.
typedef struct v8host_callbacks {
  uint32_t struct_size;  // = sizeof(v8host_callbacks)
  void* context;         // passed back to every callback below
  v8host_session_state_cb on_session_state;
  v8host_run_event_cb on_run_event;
  v8host_relay_message_cb on_relay_message;
  v8host_broker_disconnect_cb on_broker_disconnect;
} v8host_callbacks;

// Process-idempotent and thread-safe. The first successful call must occur on
// the consumer's callback/app thread, which must have a Windows message queue;
// that thread becomes the callback thread for the process.
V8HOST_API v8host_status V8HOST_CDECL v8host_initialize(void);

// Validate and copy `config`, then begin connecting a session. A synchronous
// v8host_status_ok means the inputs were accepted, not that the session is connected;
// the outcome arrives via the session callback. On failure *out_session = NULL.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_open(
    const V8HostSessionConfig* config,
    v8host_session_s** out_session);

// Install (copy) the callback table for `session`, replacing any prior table.
// Status-returning so callers can observe a rejected table (bad struct_size,
// closed session, allocation failure) rather than install silently.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_set_callbacks(
    v8host_session_s* session,
    const v8host_callbacks* callbacks);

// Validate and copy `inputs`, then begin a run on `session`. A synchronous
// v8host_status_ok means the inputs were accepted; the run outcome arrives via the run
// callback. On failure *out_run = NULL.
V8HOST_API v8host_status V8HOST_CDECL v8host_session_start_run(
    v8host_session_s* session,
    const V8HostRunInputs* inputs,
    v8host_run_s** out_run);

// Queue an outbound relay frame to the worker for `run`. `data`/`len` are copied
// before this call returns. A terminal run rejects with v8host_status_run_terminal.
// Transport admission may immediately return v8host_status_connect_failed, v8host_status_protocol_error,
// or v8host_status_quota_exceeded (nothing queued; the run continues).
V8HOST_API v8host_status V8HOST_CDECL v8host_run_post_message(
    v8host_run_s* run,
    int32_t kind,
    const void* data,
    size_t len);

// Request cancellation of `run`. Success means the request was accepted, not
// that guest code had not already produced effects. A terminal run rejects with
// v8host_status_run_terminal. Transport admission may immediately return
// v8host_status_connect_failed, v8host_status_protocol_error, or v8host_status_quota_exceeded (nothing queued).
V8HOST_API v8host_status V8HOST_CDECL v8host_run_cancel(
    v8host_run_s* run);

// Close `session` and invalidate all of its run handles. Nonblocking: it marks
// the session closed, suppresses queued callbacks, starts a best-effort close,
// and returns without waiting on broker I/O. Safe to call from within a
// callback. Always succeeds, so there is no status to report.
V8HOST_API void V8HOST_CDECL v8host_session_close(
    v8host_session_s* session);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // V8HOST_CLIENT_H_
