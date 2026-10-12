/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 *
 * Portions derived from facebook/hermes (Hermes ABI):
 *   Copyright (c) Meta Platforms, Inc. and affiliates.
 *   Licensed under the MIT license.
 *
 * JSI ABI — an ABI-stable C interface for JSI (JavaScript Interface).
 *
 * Derived from Meta's Hermes ABI: renamed to be engine-agnostic, with
 * additional changes and improvements.
 *
 * Pure C header. No engine-specific types. Can be used by any JS engine
 * (Hermes, V8, JSC).
 */

/* ===========================================================================
 * EXPERIMENTAL API - NOT YET ABI-STABLE
 *
 * This API is experimental and subject to change. Although it is C-based, it is
 * NOT ABI-safe yet: function signatures, function-table layouts, struct fields, enum
 * values, and error codes may change without notice while the API remains in
 * experimental mode. Do not depend on binary compatibility across builds. Once
 * the API leaves experimental mode it will become ABI-stable and this notice
 * will be removed.
 * =========================================================================== */

#ifndef JSI_ABI_H_
#define JSI_ABI_H_

#include <stddef.h>
#include <stdint.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*==========================================================================
 * Platform Macros
 *==========================================================================*/

/* Calling convention: __cdecl on Windows (it matters on x86), empty elsewhere. */
#ifndef JSI_ABI_CDECL
#ifdef _WIN32
#define JSI_ABI_CDECL __cdecl
#else
#define JSI_ABI_CDECL
#endif
#endif

/* Exports only while the implementing library builds (JSI_ABI_IMPL defined).
 * Consumers get it empty, or may predefine it as __declspec(dllimport). */
#ifndef JSI_ABI_API
#ifdef JSI_ABI_IMPL
#ifdef _WIN32
#define JSI_ABI_API __declspec(dllexport)
#else
#define JSI_ABI_API __attribute__((visibility("default")))
#endif
#else
#define JSI_ABI_API
#endif
#endif

/*==========================================================================
 * ABI Version
 *
 * Monotonic integer (Node-API NAPI_VERSION style). Bump by 1 for every
 * additive change — there is no major/minor split because the ABI is strictly
 * append-only with behavioral pinning. The consumer's compiled-against value is
 * passed to the engine's create function (e.g. v8_jsi_abi_runtime_create), which pins
 * the runtime to it or fails if it exceeds the implementation's max (Model B).
 *==========================================================================*/

#define JSI_ABI_VERSION 1u

/*==========================================================================
 * Forward Declarations
 *==========================================================================*/

typedef struct jsi_runtime jsi_runtime;
typedef struct jsi_runtime_api jsi_runtime_api;
typedef struct jsi_pointer jsi_pointer;
typedef struct jsi_pointer_api jsi_pointer_api;
typedef struct jsi_object jsi_object;
typedef struct jsi_array jsi_array;
typedef struct jsi_string jsi_string;
typedef struct jsi_bigint jsi_bigint;
typedef struct jsi_symbol jsi_symbol;
typedef struct jsi_function jsi_function;
typedef struct jsi_arraybuffer jsi_arraybuffer;
typedef struct jsi_propnameid jsi_propnameid;
typedef struct jsi_weak_object jsi_weak_object;
typedef struct jsi_value jsi_value;
typedef struct jsi_growable_buffer jsi_growable_buffer;
typedef struct jsi_growable_buffer_api jsi_growable_buffer_api;
typedef struct jsi_buffer jsi_buffer;
typedef struct jsi_buffer_api jsi_buffer_api;
typedef struct jsi_mutable_buffer jsi_mutable_buffer;
typedef struct jsi_mutable_buffer_api jsi_mutable_buffer_api;
typedef struct jsi_prepared_javascript jsi_prepared_javascript;
typedef struct jsi_prepared_javascript_api jsi_prepared_javascript_api;
typedef struct jsi_host_function jsi_host_function;
typedef struct jsi_host_function_api jsi_host_function_api;
typedef struct jsi_propnameid_list jsi_propnameid_list;
typedef struct jsi_propnameid_list_api jsi_propnameid_list_api;
typedef struct jsi_host_object jsi_host_object;
typedef struct jsi_host_object_api jsi_host_object_api;
typedef struct jsi_native_state jsi_native_state;
typedef struct jsi_native_state_api jsi_native_state_api;
typedef struct jsi_interface_id jsi_interface_id;
typedef struct jsi_object_or_error jsi_object_or_error;
typedef struct jsi_array_or_error jsi_array_or_error;
typedef struct jsi_string_or_error jsi_string_or_error;
typedef struct jsi_bigint_or_error jsi_bigint_or_error;
typedef struct jsi_symbol_or_error jsi_symbol_or_error;
typedef struct jsi_function_or_error jsi_function_or_error;
typedef struct jsi_arraybuffer_or_error jsi_arraybuffer_or_error;
typedef struct jsi_propnameid_or_error jsi_propnameid_or_error;
typedef struct jsi_weak_object_or_error jsi_weak_object_or_error;
typedef struct jsi_bool_or_error jsi_bool_or_error;
typedef struct jsi_size_or_error jsi_size_or_error;
typedef struct jsi_uint8_ptr_or_error jsi_uint8_ptr_or_error;
typedef struct jsi_value_or_error jsi_value_or_error;
typedef struct jsi_prepared_javascript_or_error jsi_prepared_javascript_or_error;
typedef struct jsi_propnameid_list_or_error jsi_propnameid_list_or_error;

/* Opaque, engine-agnostic configuration object. The runtime factory (e.g.
 * v8_jsi_abi_runtime_create) allocates one and hands it to a jsi_configure_runtime_cb
 * so the consumer can populate it via engine-specific setters (e.g.
 * v8_jsi_abi_config_set_*); the handle is valid ONLY for that callback's duration.
 * Layout is owned by the engine implementation. */
typedef struct jsi_config_s* jsi_config;

/* Standard data-deleter callback used when ownership of a buffer or other
 * pointer crosses the DLL boundary. The implementation that handed the
 * pointer over also supplies this callback so the consumer can free it
 * with the same allocator that allocated it. */
typedef void(JSI_ABI_CDECL *jsi_data_delete_cb)(void *data, void *deleter_data);

/*==========================================================================
 * Error Codes
 *==========================================================================*/

/* Error codes are odd values (bit 0 = 1) and 0 means "no error".
 * This lets bit-packed OrError variants encode the error directly
 * (no shift), and lets void-returning operations return jsi_status
 * directly with 0 = success / odd = error. Future codes must be odd. */
typedef enum jsi_status {
  jsi_status_ok = 0,
  jsi_status_native_error = 1, /* Native C++ exception (message available) */
  jsi_status_js_error = 3 /* JavaScript exception (JS value available) */
} jsi_status;

/*==========================================================================
 * Configure callback (factory-owned pull model)
 *==========================================================================*/

/* The runtime factory allocates a jsi_config and invokes this callback so the
 * consumer can populate it via the engine's typed setters. The config handle is
 * valid ONLY for the duration of the call. Return jsi_status_ok to proceed, or
 * an odd jsi_status to abort creation (the factory then frees the config
 * and the create call returns NULL). May be NULL at the create site, meaning
 * "all defaults". */
typedef jsi_status(JSI_ABI_CDECL *jsi_configure_runtime_cb)(
    void *user_data,
    jsi_config config);

/*==========================================================================
 * Pointer Types (from Hermes ABI pattern)
 *
 * ManagedPointer — reference-counted GC root, released through its api table.
 * Each pointer type wraps a jsi_pointer* to indicate the JS type.
 *
 * OrError variants come in two layouts, depending on whether the success
 * payload leaves a free bit for tagging:
 *
 * (A) Bit-packed (single uintptr_t). Used by every jsi_<ptr>_or_error
 *     (jsi_object_or_error, jsi_string_or_error, ...) and by
 *     jsi_bool_or_error. Discriminated by bit 0:
 *
 *       bit 0 = 0 : success.
 *                     pointer types — field is jsi_pointer* cast to
 *                                     uintptr_t (relies on jsi_pointer
 *                                     alignment >= 2 so bit 0 is 0).
 *                     jsi_bool_or_error — field is (val << 1):
 *                                         false = 0, true = 2.
 *                                         Decoder: field != 0.
 *       bit 0 = 1 : error. Field is the jsi_status value directly
 *                          (all error codes are odd; see enum above).
 *                          No shift is needed for either construction
 *                          or decoding.
 *
 * (B) Struct with explicit is_error flag + union. Used by
 *     jsi_size_or_error and jsi_uint8_ptr_or_error — their payloads use
 *     the full uintptr_t and leave no room for a tag bit.
 *
 * Void-returning operations skip the OrError wrapper entirely and return
 * jsi_status directly (0 = success, odd = error).
 *
 * Note: layout (A) stores a bare uintptr_t (not a union of jsi_pointer*
 * and uintptr_t). The tag bit shares the word with the pointer, so checking
 * it via a union would mean reading a non-active member — strict-reading
 * UB in C++. The pointer<->uintptr_t round-trip via reinterpret_cast is
 * explicitly well-defined ([expr.reinterpret.cast]/5).
 *
 * Construction and decoding helpers for both layouts live in
 * jsi_abi_helpers.h (create_*_or_error, is_error, get_error, get_*).
 *
 * NOTE: We intentionally spell out each type explicitly instead of using
 * X-macros (like Hermes ABI's HERMES_ABI_POINTER_TYPES macro). Explicit
 * declarations are debugger-friendly (F12/Go to Definition works), visible
 * to IntelliSense, and easier to read and maintain.
 *==========================================================================*/

struct jsi_pointer_api {
  void(JSI_ABI_CDECL *invalidate)(jsi_pointer *self);
};
struct jsi_pointer {
  const jsi_pointer_api *api;
};

/* --- Object --- */
struct jsi_object {
  jsi_pointer *pointer;
};
struct jsi_object_or_error {
  uintptr_t ptr_or_error;
};

/* --- Array --- */
struct jsi_array {
  jsi_pointer *pointer;
};
struct jsi_array_or_error {
  uintptr_t ptr_or_error;
};

/* --- String --- */
struct jsi_string {
  jsi_pointer *pointer;
};
struct jsi_string_or_error {
  uintptr_t ptr_or_error;
};

/* --- BigInt --- */
struct jsi_bigint {
  jsi_pointer *pointer;
};
struct jsi_bigint_or_error {
  uintptr_t ptr_or_error;
};

/* --- Symbol --- */
struct jsi_symbol {
  jsi_pointer *pointer;
};
struct jsi_symbol_or_error {
  uintptr_t ptr_or_error;
};

/* --- Function --- */
struct jsi_function {
  jsi_pointer *pointer;
};
struct jsi_function_or_error {
  uintptr_t ptr_or_error;
};

/* --- ArrayBuffer --- */
struct jsi_arraybuffer {
  jsi_pointer *pointer;
};
struct jsi_arraybuffer_or_error {
  uintptr_t ptr_or_error;
};

/* --- PropNameID --- */
struct jsi_propnameid {
  jsi_pointer *pointer;
};
struct jsi_propnameid_or_error {
  uintptr_t ptr_or_error;
};

/* --- WeakObject --- */
struct jsi_weak_object {
  jsi_pointer *pointer;
};
struct jsi_weak_object_or_error {
  uintptr_t ptr_or_error;
};

/* --- Bool-or-error (bit-packing scheme; see big-box comment above) ---
 * Void-returning operations return jsi_status directly (no wrapper);
 * 0 means success, odd values are errors. */
struct jsi_bool_or_error {
  uintptr_t bool_or_error;
};

/* --- Size and uint8_t* or-error (explicit is_error field) --- */
struct jsi_size_or_error {
  bool is_error;
  union {
    size_t val;
    jsi_status error;
  } data;
};
struct jsi_uint8_ptr_or_error {
  bool is_error;
  union {
    uint8_t *val;
    jsi_status error;
  } data;
};

/*==========================================================================
 * Value Representation (inline tagged union — from Hermes ABI)
 *==========================================================================*/

/* The POINTER_MASK marks value kinds that contain a jsi_pointer*. */
#define JSI_ABI_POINTER_MASK (1u << (sizeof(uint32_t) * 8u - 1u))

typedef enum jsi_valuekind {
  jsi_valuekind_undefined = 0,
  jsi_valuekind_null = 1,
  jsi_valuekind_boolean = 2,
  jsi_valuekind_error = 3, /* Internal: used in jsi_value_or_error */
  jsi_valuekind_number = 4,
  jsi_valuekind_symbol = 5 | JSI_ABI_POINTER_MASK,
  jsi_valuekind_bigint = 6 | JSI_ABI_POINTER_MASK,
  jsi_valuekind_string = 7 | JSI_ABI_POINTER_MASK,
  jsi_valuekind_object = 9 | JSI_ABI_POINTER_MASK
} jsi_valuekind;

struct jsi_value {
  jsi_valuekind kind;
  union {
    bool boolean;
    double number;
    jsi_pointer *pointer;
    jsi_status error; /* Only when kind == jsi_valuekind_error */
  } data;
};

struct jsi_value_or_error {
  jsi_value value;
};

/*==========================================================================
 * Buffer Types (from Hermes ABI)
 *
 * Three flavors with different ownership / lifetime semantics:
 *
 *   jsi_growable_buffer  — short-lived output parameter. Caller stack-
 *                          allocates and passes &buf for the DLL to fill
 *                          in during one call. The DLL only ever calls
 *                          try_grow_to to expand it; ownership stays with
 *                          the caller, so no release callback is needed.
 *
 *   jsi_buffer           — read-only input the DLL retains past the call
 *                          (e.g., script source). Consumer heap-allocates;
 *                          the DLL calls api->release when done.
 *
 *   jsi_mutable_buffer   — writable backing the DLL retains past the call
 *                          (e.g., ArrayBuffer storage). Same release
 *                          contract as jsi_buffer.
 *==========================================================================*/

struct jsi_growable_buffer_api {
  void(JSI_ABI_CDECL *try_grow_to)(jsi_growable_buffer *buf, size_t sz);
};
struct jsi_growable_buffer {
  const jsi_growable_buffer_api *api;
  uint8_t *data;
  size_t size;
  size_t used;
};

struct jsi_buffer_api {
  void(JSI_ABI_CDECL *release)(jsi_buffer *self);
};
struct jsi_buffer {
  const jsi_buffer_api *api;
  const uint8_t *data;
  size_t size;
};

struct jsi_mutable_buffer_api {
  void(JSI_ABI_CDECL *release)(jsi_mutable_buffer *self);
};
struct jsi_mutable_buffer {
  const jsi_mutable_buffer_api *api;
  uint8_t *data;
  size_t size;
};

/*==========================================================================
 * PreparedJavaScript
 *
 * Opaque engine-managed handle to a compiled script. Returned by
 * prepare_javascript; passed (by pointer) to evaluate_prepared_javascript.
 * Always carried by pointer so the implementation can append fields beyond
 * the api field without breaking ABI for callers that only see the
 * base layout.
 *
 * Lifecycle: the consumer owns the returned pointer and calls
 * api->release(p) when done.
 *==========================================================================*/

struct jsi_prepared_javascript_api {
  void(JSI_ABI_CDECL *release)(jsi_prepared_javascript *self);
};
struct jsi_prepared_javascript {
  const jsi_prepared_javascript_api *api;
  /* Implementation may append fields after this header. */
};
struct jsi_prepared_javascript_or_error {
  uintptr_t ptr_or_error;
};

/*==========================================================================
 * Callback Types (embedded-struct pattern — from Hermes ABI)
 *==========================================================================*/

/* Host function: called when JS invokes a native function. */
struct jsi_host_function_api {
  void(JSI_ABI_CDECL *release)(jsi_host_function *);
  jsi_value_or_error(JSI_ABI_CDECL *call)(
      jsi_host_function *self,
      jsi_runtime *rt,
      const jsi_value *this_arg,
      const jsi_value *args,
      size_t arg_count);
};
struct jsi_host_function {
  const jsi_host_function_api *api;
};

/* PropNameID list: returned by host object get_own_keys. */
struct jsi_propnameid_list_api {
  void(JSI_ABI_CDECL *release)(jsi_propnameid_list *);
};
struct jsi_propnameid_list {
  const jsi_propnameid_list_api *api;
  const jsi_propnameid *props;
  size_t size;
};

struct jsi_propnameid_list_or_error {
  uintptr_t ptr_or_error;
};

/* Host object: JS object backed by native callbacks. */
struct jsi_host_object_api {
  void(JSI_ABI_CDECL *release)(jsi_host_object *);
  jsi_value_or_error(JSI_ABI_CDECL *get)(
      jsi_host_object *self,
      jsi_runtime *rt,
      jsi_propnameid name);
  jsi_status(JSI_ABI_CDECL *set)(
      jsi_host_object *self,
      jsi_runtime *rt,
      jsi_propnameid name,
      const jsi_value *value);
  jsi_propnameid_list_or_error(JSI_ABI_CDECL *get_own_keys)(
      jsi_host_object *self,
      jsi_runtime *rt);
};
struct jsi_host_object {
  const jsi_host_object_api *api;
};

/* Native state: attached to JS objects, released on GC. */
struct jsi_native_state_api {
  void(JSI_ABI_CDECL *release)(jsi_native_state *self);
};
struct jsi_native_state {
  const jsi_native_state_api *api;
};

/*==========================================================================
 * Interface Query (for optional extensions — like JSI C++ ICast)
 *==========================================================================*/

struct jsi_interface_id {
  uint64_t lower;
  uint64_t upper;
};

/*==========================================================================
 * Runtime VTable
 *==========================================================================*/

struct jsi_runtime_api {
  /* Pure function table — no version/reserved data fields. Version negotiation
   * happens once at create time (see JSI_ABI_VERSION / v8_jsi_abi_runtime_create). New
   * functions are appended at the END of this struct. */

  /*----------------------------------------------------------------------
   * QueryInterface / ICast (C++ JSI: castInterface)
   * Placed first — like COM's QueryInterface at slot 0. Allows consumers to
   * discover capabilities before calling anything else.
   *----------------------------------------------------------------------*/

  /* Query for an optional interface extension.
   * Returns jsi_status_native_error with empty message if not supported. */
  jsi_status(JSI_ABI_CDECL *query_interface)(
      jsi_runtime *rt,
      const jsi_interface_id *iid,
      const void **vtable_out,
      void **instance_out);

  /* Report the implementation's max supported ABI version (Node-API
   * napi_get_version analog). Optional feature-probe — the create-time version
   * negotiation in v8_jsi_abi_runtime_create is what actually gates. */
  uint32_t(JSI_ABI_CDECL *get_abi_version)(jsi_runtime *rt);

  /*----------------------------------------------------------------------
   * Lifecycle
   *
   * The runtime is reference-counted. v8_jsi_abi_runtime_create / jsr_create_runtime
   * hand back a runtime with refcount 1. Each add_ref increments; each
   * release decrements and destroys the runtime when the count reaches 0.
   *----------------------------------------------------------------------*/

  void(JSI_ABI_CDECL *add_ref)(jsi_runtime *);
  void(JSI_ABI_CDECL *release)(jsi_runtime *);

  /*----------------------------------------------------------------------
   * Error retrieval (from Hermes ABI pattern)
   *----------------------------------------------------------------------*/

  /* Get and clear the JS exception value (after jsi_status_js_error). */
  jsi_value(JSI_ABI_CDECL *get_and_clear_js_error_value)(
      jsi_runtime *rt);

  /* Get and clear native exception message (after jsi_status_native_error). */
  void(JSI_ABI_CDECL *get_and_clear_native_exception_message)(
      jsi_runtime *rt,
      jsi_growable_buffer *buf);

  /* Set errors before returning from host function/object callbacks. */
  void(JSI_ABI_CDECL *set_js_error_value)(
      jsi_runtime *rt,
      const jsi_value *error_value);
  void(JSI_ABI_CDECL *set_native_exception_message_utf8)(
      jsi_runtime *rt,
      const uint8_t *utf8,
      size_t length);

  /*----------------------------------------------------------------------
   * Clone operations (from Hermes ABI)
   *----------------------------------------------------------------------*/

  jsi_propnameid(JSI_ABI_CDECL *clone_propnameid)(
      jsi_runtime *rt,
      jsi_propnameid name);
  jsi_string(JSI_ABI_CDECL *clone_string)(
      jsi_runtime *rt,
      jsi_string str);
  jsi_symbol(JSI_ABI_CDECL *clone_symbol)(
      jsi_runtime *rt,
      jsi_symbol sym);
  jsi_object(JSI_ABI_CDECL *clone_object)(
      jsi_runtime *rt,
      jsi_object obj);
  jsi_bigint(JSI_ABI_CDECL *clone_bigint)(
      jsi_runtime *rt,
      jsi_bigint bigint);

  /*----------------------------------------------------------------------
   * Runtime description and capabilities
   *----------------------------------------------------------------------*/

  void(JSI_ABI_CDECL *get_description)(
      jsi_runtime *rt,
      jsi_growable_buffer *buf);
  bool(JSI_ABI_CDECL *is_inspectable)(jsi_runtime *rt);

  /*----------------------------------------------------------------------
   * Handle scopes
   *----------------------------------------------------------------------*/

  /* Push a new handle scope. All pointer types created after this call
   * are valid until pop_scope. Engines that don't need scopes (Hermes)
   * can implement these as no-ops. */
  jsi_status(JSI_ABI_CDECL *push_scope)(
      jsi_runtime *rt,
      void **scope);
  jsi_status(JSI_ABI_CDECL *pop_scope)(
      jsi_runtime *rt,
      void *scope);

  /*----------------------------------------------------------------------
   * Script evaluation
   *----------------------------------------------------------------------*/

  jsi_value_or_error(JSI_ABI_CDECL *evaluate_javascript_source)(
      jsi_runtime *rt,
      jsi_buffer *buf,
      const char *source_url,
      size_t source_url_len);

  /* Prepare (compile) a script for later execution. The returned
   * jsi_prepared_javascript* is owned by the caller and freed via
   * api->release. */
  jsi_prepared_javascript_or_error(JSI_ABI_CDECL *prepare_javascript)(
      jsi_runtime *rt,
      jsi_buffer *buf,
      const char *source_url,
      size_t source_url_len);
  jsi_value_or_error(JSI_ABI_CDECL *evaluate_prepared_javascript)(
      jsi_runtime *rt,
      jsi_prepared_javascript *prepared);

  /*----------------------------------------------------------------------
   * Microtasks
   *----------------------------------------------------------------------*/

  jsi_bool_or_error(JSI_ABI_CDECL *drain_microtasks)(
      jsi_runtime *rt,
      int32_t max_hint);
  jsi_status(JSI_ABI_CDECL *queue_microtask)(
      jsi_runtime *rt,
      jsi_function callback);

  /*----------------------------------------------------------------------
   * Global object
   *----------------------------------------------------------------------*/

  jsi_object(JSI_ABI_CDECL *get_global_object)(jsi_runtime *rt);

  /*----------------------------------------------------------------------
   * String operations
   *----------------------------------------------------------------------*/

  jsi_string_or_error(JSI_ABI_CDECL *create_string_utf8)(
      jsi_runtime *rt,
      const uint8_t *utf8,
      size_t len);
  jsi_string_or_error(JSI_ABI_CDECL *create_string_utf16)(
      jsi_runtime *rt,
      const uint16_t *utf16,
      size_t len);
  void(JSI_ABI_CDECL *get_string_utf8)(
      jsi_runtime *rt,
      jsi_string str,
      jsi_growable_buffer *buf);
  void(JSI_ABI_CDECL *get_string_utf16)(
      jsi_runtime *rt,
      jsi_string str,
      jsi_growable_buffer *buf);

  /*----------------------------------------------------------------------
   * Symbol operations
   *----------------------------------------------------------------------*/

  void(JSI_ABI_CDECL *get_symbol_utf8)(
      jsi_runtime *rt,
      jsi_symbol sym,
      jsi_growable_buffer *buf);

  /*----------------------------------------------------------------------
   * PropNameID operations
   *----------------------------------------------------------------------*/

  jsi_propnameid_or_error(JSI_ABI_CDECL *create_propnameid_utf8)(
      jsi_runtime *rt,
      const uint8_t *utf8,
      size_t len);
  jsi_propnameid_or_error(JSI_ABI_CDECL *create_propnameid_from_string)(
      jsi_runtime *rt,
      jsi_string str);
  jsi_propnameid_or_error(JSI_ABI_CDECL *create_propnameid_from_symbol)(
      jsi_runtime *rt,
      jsi_symbol sym);
  bool(JSI_ABI_CDECL *propnameid_equals)(
      jsi_runtime *rt,
      jsi_propnameid a,
      jsi_propnameid b);
  void(JSI_ABI_CDECL *get_propnameid_utf8)(
      jsi_runtime *rt,
      jsi_propnameid name,
      jsi_growable_buffer *buf);

  /*----------------------------------------------------------------------
   * Object operations
   *----------------------------------------------------------------------*/

  jsi_object_or_error(JSI_ABI_CDECL *create_object)(
      jsi_runtime *rt);
  jsi_object_or_error(JSI_ABI_CDECL *create_object_with_prototype)(
      jsi_runtime *rt,
      const jsi_value *prototype);

  /* Prototype access */
  jsi_value_or_error(JSI_ABI_CDECL *get_prototype_of)(
      jsi_runtime *rt,
      jsi_object obj);
  jsi_status(JSI_ABI_CDECL *set_prototype_of)(
      jsi_runtime *rt,
      jsi_object obj,
      const jsi_value *prototype);

  /* Property operations (PropNameID-based) */
  jsi_bool_or_error(JSI_ABI_CDECL *has_object_property_from_propnameid)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_propnameid name);
  jsi_value_or_error(JSI_ABI_CDECL *get_object_property_from_propnameid)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_propnameid name);
  jsi_status(JSI_ABI_CDECL *set_object_property_from_propnameid)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_propnameid name,
      const jsi_value *value);
  jsi_status(JSI_ABI_CDECL *delete_property_from_propnameid)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_propnameid name);

  /* Property operations (Value-based — key can be string, symbol, number) */
  jsi_bool_or_error(JSI_ABI_CDECL *has_object_property_from_value)(
      jsi_runtime *rt,
      jsi_object obj,
      const jsi_value *key);
  jsi_value_or_error(JSI_ABI_CDECL *get_object_property_from_value)(
      jsi_runtime *rt,
      jsi_object obj,
      const jsi_value *key);
  jsi_status(JSI_ABI_CDECL *set_object_property_from_value)(
      jsi_runtime *rt,
      jsi_object obj,
      const jsi_value *key,
      const jsi_value *value);
  jsi_status(JSI_ABI_CDECL *delete_property_from_value)(
      jsi_runtime *rt,
      jsi_object obj,
      const jsi_value *key);

  /* Get enumerable string property names. */
  jsi_array_or_error(JSI_ABI_CDECL *get_object_property_names)(
      jsi_runtime *rt,
      jsi_object obj);

  /* External memory pressure hint for GC. */
  jsi_status(JSI_ABI_CDECL *set_object_external_memory_pressure)(
      jsi_runtime *rt,
      jsi_object obj,
      size_t amount);

  /* Error object creation */
  jsi_object_or_error(JSI_ABI_CDECL *create_error_utf8)(
      jsi_runtime *rt,
      const uint8_t *utf8_msg,
      size_t len);

  /*----------------------------------------------------------------------
   * Array operations
   *----------------------------------------------------------------------*/

  jsi_array_or_error(JSI_ABI_CDECL *create_array)(
      jsi_runtime *rt,
      size_t length);
  size_t(JSI_ABI_CDECL *get_array_length)(
      jsi_runtime *rt,
      jsi_array arr);
  jsi_value_or_error(JSI_ABI_CDECL *get_array_element)(
      jsi_runtime *rt,
      jsi_object arr,
      size_t index);
  jsi_status(JSI_ABI_CDECL *set_array_element)(
      jsi_runtime *rt,
      jsi_object arr,
      size_t index,
      const jsi_value *value);

  /*----------------------------------------------------------------------
   * ArrayBuffer operations
   *----------------------------------------------------------------------*/

  jsi_arraybuffer_or_error(JSI_ABI_CDECL *create_arraybuffer)(
      jsi_runtime *rt,
      size_t byte_length);
  jsi_arraybuffer_or_error(
      JSI_ABI_CDECL *create_arraybuffer_from_external_data)(
      jsi_runtime *rt,
      jsi_mutable_buffer *buf);
  jsi_uint8_ptr_or_error(JSI_ABI_CDECL *get_arraybuffer_data)(
      jsi_runtime *rt,
      jsi_arraybuffer ab);
  jsi_size_or_error(JSI_ABI_CDECL *get_arraybuffer_size)(
      jsi_runtime *rt,
      jsi_arraybuffer ab);

  /*----------------------------------------------------------------------
   * Function operations
   *----------------------------------------------------------------------*/

  jsi_value_or_error(JSI_ABI_CDECL *call)(
      jsi_runtime *rt,
      jsi_function fn,
      const jsi_value *js_this,
      const jsi_value *args,
      size_t arg_count);
  jsi_value_or_error(JSI_ABI_CDECL *call_as_constructor)(
      jsi_runtime *rt,
      jsi_function fn,
      const jsi_value *args,
      size_t arg_count);
  jsi_function_or_error(JSI_ABI_CDECL *create_function_from_host_function)(
      jsi_runtime *rt,
      jsi_propnameid name,
      uint32_t param_count,
      jsi_host_function *hf);
  jsi_host_function *(JSI_ABI_CDECL *get_host_function)(
      jsi_runtime *rt,
      jsi_function fn);

  /*----------------------------------------------------------------------
   * Host object operations
   *----------------------------------------------------------------------*/

  jsi_object_or_error(JSI_ABI_CDECL *create_object_from_host_object)(
      jsi_runtime *rt,
      jsi_host_object *ho);
  jsi_host_object *(JSI_ABI_CDECL *get_host_object)(
      jsi_runtime *rt,
      jsi_object obj);

  /*----------------------------------------------------------------------
   * Native state
   *----------------------------------------------------------------------*/

  bool(JSI_ABI_CDECL *has_native_state)(
      jsi_runtime *rt,
      jsi_object obj);
  jsi_native_state *(JSI_ABI_CDECL *get_native_state)(
      jsi_runtime *rt,
      jsi_object obj);
  jsi_status(JSI_ABI_CDECL *set_native_state)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_native_state *ns);

  /*----------------------------------------------------------------------
   * Type checks
   *----------------------------------------------------------------------*/

  bool(JSI_ABI_CDECL *object_is_array)(
      jsi_runtime *rt,
      jsi_object obj);
  bool(JSI_ABI_CDECL *object_is_arraybuffer)(
      jsi_runtime *rt,
      jsi_object obj);
  bool(JSI_ABI_CDECL *object_is_function)(
      jsi_runtime *rt,
      jsi_object obj);

  /*----------------------------------------------------------------------
   * Weak references
   *----------------------------------------------------------------------*/

  jsi_weak_object_or_error(JSI_ABI_CDECL *create_weak_object)(
      jsi_runtime *rt,
      jsi_object obj);
  jsi_value(JSI_ABI_CDECL *lock_weak_object)(
      jsi_runtime *rt,
      jsi_weak_object wo);

  /*----------------------------------------------------------------------
   * Comparison
   *----------------------------------------------------------------------*/

  jsi_bool_or_error(JSI_ABI_CDECL *instance_of)(
      jsi_runtime *rt,
      jsi_object obj,
      jsi_function ctor);
  bool(JSI_ABI_CDECL *strict_equals_symbol)(
      jsi_runtime *rt,
      jsi_symbol a,
      jsi_symbol b);
  bool(JSI_ABI_CDECL *strict_equals_bigint)(
      jsi_runtime *rt,
      jsi_bigint a,
      jsi_bigint b);
  bool(JSI_ABI_CDECL *strict_equals_string)(
      jsi_runtime *rt,
      jsi_string a,
      jsi_string b);
  bool(JSI_ABI_CDECL *strict_equals_object)(
      jsi_runtime *rt,
      jsi_object a,
      jsi_object b);

  /*----------------------------------------------------------------------
   * BigInt
   *----------------------------------------------------------------------*/

  jsi_bigint_or_error(JSI_ABI_CDECL *create_bigint_from_int64)(
      jsi_runtime *rt,
      int64_t value);
  jsi_bigint_or_error(JSI_ABI_CDECL *create_bigint_from_uint64)(
      jsi_runtime *rt,
      uint64_t value);
  bool(JSI_ABI_CDECL *bigint_is_int64)(
      jsi_runtime *rt,
      jsi_bigint bigint);
  bool(JSI_ABI_CDECL *bigint_is_uint64)(
      jsi_runtime *rt,
      jsi_bigint bigint);
  uint64_t(JSI_ABI_CDECL *bigint_truncate_to_uint64)(
      jsi_runtime *rt,
      jsi_bigint bigint);
  int64_t(JSI_ABI_CDECL *bigint_to_int64)(
      jsi_runtime *rt,
      jsi_bigint bigint,
      bool *lossless);
  uint64_t(JSI_ABI_CDECL *bigint_to_uint64)(
      jsi_runtime *rt,
      jsi_bigint bigint,
      bool *lossless);
  jsi_string_or_error(JSI_ABI_CDECL *bigint_to_string)(
      jsi_runtime *rt,
      jsi_bigint bigint,
      uint32_t radix);
};

/*==========================================================================
 * Runtime Instance
 *==========================================================================*/

struct jsi_runtime {
  const jsi_runtime_api *api;
};

#ifdef __cplusplus
}
#endif

#endif /* JSI_ABI_H_ */
