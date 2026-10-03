# Sandbox engine payload (`v8host.dll`)

`v8host.dll` is the engine payload driven by the product `sbox.exe` container.
`sbox.exe` is generic: the app knowledge lives here, in a plugin resolved by
`--plugin v8host.dll`. The container owns `main()` and drives the plugin-ABI
lifecycle — `configure` (broker) → `warmup` pre-lockdown → `lower_token` → `run`
post-lockdown → `shutdown`. The payload exports only the single
`sbox_plugin_main` entry (see [`sbox.h`](../sandbox_dll/sbox.h)), which returns a
vtable of those four functions. It links the JSI C++ API (`jsi_cpp`) but **never
the sandbox core** — it reaches the message channel only through the
`sbox_worker_api` function pointers the container hands it. This replaces the
retired two-image topology where a `v8host.exe` target owned `main()` and loaded
`sbox.dll`.

## Status: real V8/JSI engine

The current `v8host.dll` is built from
[`v8host_engine.cc`](./v8host_engine.cc) — the **real V8/JSI engine** carved from
the retired `v8host.exe` main, split at the `LowerToken` boundary and exposed as
the plugin vtable:

- **`configure` (broker):** describes the sandbox the worker will run in — arms
  ACG and sets integrity for the Untrusted (jitless) tier, leaves ACG off for
  Trusted (JIT), declares the engine DLL for the broker to Authenticode-verify,
  and encodes the run profile (engine DLL, jitless flag, optional snapshot path)
  into the opaque `plugin_data` the container carries to the worker. The tier and
  engine are overridable for testing via `SBOX_TIER` / `V8HOST_ENGINE_DLL` /
  `V8HOST_SNAPSHOT` in the broker's environment.
- **`warmup` (pre-lockdown):** decodes `plugin_data`, loads the engine DLL by full
  path from the app dir (`v8jsisb.dll` jitless for Untrusted, `v8jsi.dll` for
  Trusted), sets `--jitless` when the profile says so, optionally loads and
  prechecks the startup snapshot, reads the guest JS, creates the JSI runtime
  (`makeJsiAbiRuntime` over `v8_create_runtime`), and installs the `host` object.
  All codegen (engine load, snapshot deserialize, runtime create) happens
  **here**, because ACG forbids it after `lower_token`.
- **`run` (post-lockdown):** proves ACG is in force with a blocked executable
  allocation, evaluates the guest (interpreted under jitless, so safe post-ACG),
  then owns the JS thread in the WebView2-style message loop
  (`host.postMessage` / `host.postMessageBinary` → the channel; inbound frames →
  `host.onmessage`) until the broker closes the channel.
- **`shutdown`:** tears down the runtime and the engine handle.

## Engine host behavior

- With no nonempty `V8HOST_GUEST_JS`, the host installs a small built-in demo
  guest (`host.onmessage = m => host.postMessage('js echo: ' + m)`, with a binary
  branch that tags byte 0 of an in-cage `ArrayBuffer`). It posts nothing
  unprompted, so each broker request maps to exactly one `js echo:` reply.
- With `V8HOST_GUEST_JS`, the host reads that file before lockdown and runs it as
  the custom guest. An empty file is valid. A requested file that cannot be read
  is an input error, not permission to fall back to the demo.
- The host stays a neutral JS host: it installs the `host` object and evaluates
  whatever guest it is handed. A clean worker exit (`0`) means the ACG check
  passed, guest evaluation completed, and the message loop ended normally when
  the broker closed it. It does **not** certify an application-specific result
  sent by the guest — the broker and guest define that protocol.
- Failed message sends throw a JavaScript error (surfaced as a run failure).

Mandatory lockdown and verification of requested ACG are retained. Neither
custom-guest selection nor result reporting disables any security check; all
engine setup (the only place codegen is allowed) completes before
`lower_token`.

## Smoke test

Build the `generic` group and drive the single-image container, which spawns its
own `--worker`, loads `v8host.dll`, and runs the warmup → `lower_token` → run
round trip from the repository root:

```powershell
node .\scripts\sbox-build.ts --target-cpu x64 --target generic
& .\deps\chromium\out\sandbox-x64\sbox.exe --broker --plugin v8host.dll
```

A passing run shows the real-engine signals: `engine = v8jsisb.dll`, `v8jsi
runtime created (warmup, pre-lockdown)`, `LowerToken survived`,
`exec-alloc(post)=BLOCKED (ACG in force) (err=1655)`, the guest `JS evaluated =
OK`, the broker's `worker reply = "js echo: ping from broker"` (real guest JS
executed under lockdown), and `worker_exit=0 ... -> PASS`.
