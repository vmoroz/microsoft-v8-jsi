// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/* ===========================================================================
 * EXPERIMENTAL API - NOT YET ABI-STABLE
 *
 * This is the consumer-compiled client ABI for v8host.dll. A consuming app
 * compiles against this header, LoadLibrary's v8host.dll, and calls the
 * v8host_client_* entry points; no import library is required. Every entry
 * point and every function pointer uses a fixed calling convention
 * (V8HOST_CALL) so a consumer built with a different toolchain still agrees on
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
// V8HOST_CALL, so a consumer built with a different toolchain still agrees on
// the ABI. You cannot pass function pointers across a DLL boundary without a
// fixed convention.
#ifndef V8HOST_CALL
#define V8HOST_CALL __cdecl
#endif

// v8host.dll's own build defines V8HOST_CLIENT_IMPL to export the
// v8host_client_* entry points. Consumers bind by name via LoadLibrary +
// GetProcAddress, so by default the declarations carry NO import decoration and
// need no import library. A consumer that prefers to link an import library
// instead may predefine V8HOST_CLIENT_API to __declspec(dllimport).
#ifndef V8HOST_CLIENT_API
#ifdef V8HOST_CLIENT_IMPL
#define V8HOST_CLIENT_API __declspec(dllexport)
#else
#define V8HOST_CLIENT_API
#endif
#endif

// Governs the in-proc call shape only (struct layouts + entry points). The
// effective end-to-end runtime contract is the broker wire version, negotiated
// separately; this value is struct_size-checked against the loaded DLL.
#define V8HOST_CLIENT_API_VERSION 1u

// Broker mode (matches the wire endpoint_mode numbering).
#define V8HOST_BROKER_DEDICATED 0
#define V8HOST_BROKER_SHARED    1

// Security tier.
#define V8HOST_TIER_UNTRUSTED 0  // jitless + ACG (default)
#define V8HOST_TIER_TRUSTED   1  // JIT, ACG off

// Session-state codes (V8HostSessionStateCb `state`).
#define V8HOST_SESSION_STATE_CREATING               0
#define V8HOST_SESSION_STATE_READY                  1
#define V8HOST_SESSION_STATE_WORKER_STARTUP_READY   2
#define V8HOST_SESSION_STATE_WORKER_SECURITY_READY  3
#define V8HOST_SESSION_STATE_CLOSED                 4

// Run-event codes (V8HostRunEventCb `event`). All except STARTED are terminal.
#define V8HOST_RUN_EVENT_STARTED        0
#define V8HOST_RUN_EVENT_COMPLETED      1
#define V8HOST_RUN_EVENT_FAILED         2
#define V8HOST_RUN_EVENT_CANCELLED      3
#define V8HOST_RUN_EVENT_WORKER_EXITED  4
#define V8HOST_RUN_EVENT_BROKER_LOST    5

// Stable result codes. 0 is success; errors are grouped into stable bands by
// failure class so new codes can be added to a band without renumbering:
//   0x1000 - caller/argument contract and quotas (fail-closed)
//   0x2000 - lifecycle/state and local resources
//   0x3000 - broker transport / connection
//   0x4000 - asynchronous session/run terminal conditions
//   0x7000 - unexpected internal failure
// The enum is pinned to 32-bit int (see V8HOST_STATUS_FORCE_INT32), so these
// codes are ABI-compatible with a plain int return.
typedef enum V8HostStatus {
  V8HOST_OK = 0,  // success; for async calls, inputs were validated and accepted

  // 0x1000 - caller/argument contract and quotas (fail-closed).
  V8HOST_E_INVALID_ARG = 0x1001,  // NULL/invalid pointer, enum, or count/pair
  V8HOST_E_STRUCT_SIZE = 0x1002,  // struct_size < required v1 size
  V8HOST_E_VERSION     = 0x1003,  // client API / loaded-DLL ABI incompatible
  V8HOST_E_QUOTA       = 0x1004,  // a documented cap exceeded (e.g. 64/64)

  // 0x2000 - lifecycle/state and local resources.
  V8HOST_E_NOT_INITIALIZED = 0x2001,  // called before v8host_client_initialize
  V8HOST_E_INVALID_STATE   = 0x2002,  // handle closed/invalid for the operation
  V8HOST_E_NO_MEMORY       = 0x2003,  // local allocation failed

  // 0x3000 - broker transport / connection.
  V8HOST_E_CONNECT     = 0x3001,  // rendezvous / connect-or-launch failed
  V8HOST_E_PROTOCOL    = 0x3002,  // malformed or unexpected wire traffic
  V8HOST_E_BROKER_LOST = 0x3003,  // broker transport dropped (terminal)

  // 0x4000 - asynchronous session/run terminal conditions.
  V8HOST_E_RUN_TERMINAL          = 0x4001,  // post/cancel on an ended run
  V8HOST_E_CALLBACK_BACKPRESSURE = 0x4002,  // app thread not draining callbacks
  V8HOST_E_PROFILE_ALREADY_BOUND = 0x4003,  // a later start_run's tier/engine/
                                            // snapshot conflicts with the
                                            // profile bound by the first run

  // 0x7000 - unexpected internal failure.
  V8HOST_E_INTERNAL = 0x7001,

  // Not a status value: pins the enum to 32-bit int for a stable ABI.
  V8HOST_STATUS_FORCE_INT32 = 0x7fffffff
} V8HostStatus;

// Versioning discipline for the input and callback structs below: a caller sets
// struct_size = sizeof(T) before passing a struct in. The DLL rejects a struct
// smaller than its required version-1 size with V8HOST_E_STRUCT_SIZE, and reads
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
  int32_t  broker_mode;  // V8HOST_BROKER_DEDICATED | V8HOST_BROKER_SHARED
  int32_t  tier;         // default tier: V8HOST_TIER_UNTRUSTED | _TRUSTED
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

// Opaque handles. A V8HostSession owns all of its V8HostRun handles; there is no
// per-run release - run handles live until v8host_client_close_session.
typedef struct V8HostSession V8HostSession;
typedef struct V8HostRun V8HostRun;

// Callback contract (design §9.1/§9.3): every callback is invoked on the app
// (callback) thread captured by the first successful v8host_client_initialize,
// never on an internal I/O thread, and never while an internal lock is held. Any
// buffer passed to a callback is owned by v8host and valid ONLY for the duration
// of that callback - copy it if you need to retain it; the client retains none
// of your pointers. Reentrant start/post/cancel/set_callbacks/close from inside
// a callback is supported.

// Session lifecycle transition or terminal error. `state` is a session-state
// code (kept ABI-plain as int32_t). `status` is V8HOST_OK for a benign
// transition, or a terminal V8HOST_E_* code when the session has failed (e.g.
// V8HOST_E_CALLBACK_BACKPRESSURE, V8HOST_E_BROKER_LOST).
typedef void(V8HOST_CALL* V8HostSessionStateCb)(void* context,
                                                V8HostSession* session,
                                                int32_t state,
                                                V8HostStatus status);

// Run lifecycle event, including the single app-visible terminal event selected
// by the run-state arbiter. `event` is a run-event code (ABI-plain int32_t). A
// terminal event carries the run's final `status`: V8HOST_OK on clean
// completion, else a V8HOST_E_* code (e.g. V8HOST_E_RUN_TERMINAL on a
// post-terminal outcome, V8HOST_E_BROKER_LOST on disconnect).
// A broker relay-cap overflow may end a run with FAILED / V8HOST_E_QUOTA.
// A per-connection overflow also closes the connection; its other live runs
// then end with BROKER_LOST / V8HOST_E_BROKER_LOST.
typedef void(V8HOST_CALL* V8HostRunEventCb)(void* context,
                                            V8HostRun* run,
                                            int32_t event,
                                            V8HostStatus status);

// Inbound relay frame from the worker for `run`. `kind` is an app-defined
// message kind (ABI-plain int32_t). `data`/`len` are borrowed for the callback
// only.
typedef void(V8HOST_CALL* V8HostRelayMessageCb)(void* context,
                                                V8HostRun* run,
                                                int32_t kind,
                                                const void* data,
                                                size_t len);

// The broker transport dropped. Every live session and run on this connection is
// independently marked terminal with V8HOST_E_BROKER_LOST through the session
// and run callbacks; the client does not replay prior requests.
typedef void(V8HOST_CALL* V8HostBrokerDisconnectCb)(void* context);

// Versioned callback table, installed per session via
// v8host_client_set_callbacks. The table is copied on install and atomically
// replaces the prior table for FUTURE dispatch; already-queued events use the
// table snapshot captured when they were queued. Any member may be NULL to
// decline that notification.
typedef struct V8HostCallbacks {
  uint32_t struct_size;  // = sizeof(V8HostCallbacks)
  void* context;         // passed back to every callback below
  V8HostSessionStateCb on_session_state;
  V8HostRunEventCb on_run_event;
  V8HostRelayMessageCb on_relay_message;
  V8HostBrokerDisconnectCb on_broker_disconnect;
} V8HostCallbacks;

// Process-idempotent and thread-safe. The first successful call must occur on
// the consumer's callback/app thread, which must have a Windows message queue;
// that thread becomes the callback thread for the process.
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_initialize(void);

// Validate and copy `config`, then begin connecting a session. A synchronous
// V8HOST_OK means the inputs were accepted, not that the session is connected;
// the outcome arrives via the session callback. On failure *out_session = NULL.
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_create_session(
    const V8HostSessionConfig* config,
    V8HostSession** out_session);

// Install (copy) the callback table for `session`, replacing any prior table.
// Status-returning so callers can observe a rejected table (bad struct_size,
// closed session, allocation failure) rather than install silently.
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_set_callbacks(
    V8HostSession* session,
    const V8HostCallbacks* callbacks);

// Validate and copy `inputs`, then begin a run on `session`. A synchronous
// V8HOST_OK means the inputs were accepted; the run outcome arrives via the run
// callback. On failure *out_run = NULL.
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_start_run(
    V8HostSession* session,
    const V8HostRunInputs* inputs,
    V8HostRun** out_run);

// Queue an outbound relay frame to the worker for `run`. `data`/`len` are copied
// before this call returns. A terminal run rejects with V8HOST_E_RUN_TERMINAL.
// Transport admission may immediately return V8HOST_E_CONNECT, V8HOST_E_PROTOCOL,
// or V8HOST_E_QUOTA (nothing queued; the run continues).
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_post_message(
    V8HostRun* run,
    int32_t kind,
    const void* data,
    size_t len);

// Request cancellation of `run`. Success means the request was accepted, not
// that guest code had not already produced effects. A terminal run rejects with
// V8HOST_E_RUN_TERMINAL. Transport admission may immediately return
// V8HOST_E_CONNECT, V8HOST_E_PROTOCOL, or V8HOST_E_QUOTA (nothing queued).
V8HOST_CLIENT_API V8HostStatus V8HOST_CALL v8host_client_cancel_run(
    V8HostRun* run);

// Close `session` and invalidate all of its run handles. Nonblocking: it marks
// the session closed, suppresses queued callbacks, starts a best-effort close,
// and returns without waiting on broker I/O. Safe to call from within a
// callback. Always succeeds, so there is no status to report.
V8HOST_CLIENT_API void V8HOST_CALL v8host_client_close_session(
    V8HostSession* session);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // V8HOST_CLIENT_H_
