# Stela

Stela checks C ABI headers. It currently provides the annotation vocabulary,
the native extractor, and `stela vendor`. Later stages add model merging, lint
rules, ABI diff, generators, and manifests embedded in binaries. It incubates
here with no dependency on v8-jsi code, so it can move to its own repository
unchanged.

Status: stage S2, the native extractor and `stela.raw/1`.

## Requirements

- Node.js 24 or later. Stela runs TypeScript directly; there is no build step.
- For the compile-matrix tests: Visual Studio with the C++ tools and the
  "C++ Clang Compiler for Windows" component
  (`Microsoft.VisualStudio.Component.VC.Llvm.Clang`).

## Extractor

`extract/stela_extract.c` is a C17 libclang client. It parses one target and
writes deterministic `stela.raw/1` JSON. The Node helper in
`src/extractor.ts` builds it on demand with the host-native MSVC and libclang,
keys the output by the sources and libclang binary, and supplies the selected
target's MSVC and Windows SDK include paths.

The native command is:

```text
stela-extract --target <triple> --root <dir> --out <file.json>
              [--include <dir>]... [--define <NAME[=VALUE]>]...
              [--owns <path>]... <header>...
```

The default owned paths are the entry headers. Declarations are assigned by
their macro expansion location. Any parse error exits with code 2 and does not
replace an existing output.

The vendored libclang C API headers are pinned to LLVM 22.1.3. Set
`STELA_LIBCLANG_DIR` to override the host-native directory containing
`libclang.dll`; the matching import library must be in the sibling `lib`
directory.

## The annotation template

[`include/stela.h`](include/stela.h) is a template; nothing includes it.
`stela vendor` generates one `<lib>_stela.h` per library from it, with the
library's macro prefix:

- `STELA_<NAME>` becomes `<LIB>_<NAME>`: `V8HOST_NULLABLE`, `V8HOST_ENUM`.
- The internal helpers become `<LIB>_STELA_VERSION`, `<LIB>_STELA_ANNOTATE_`,
  and `<LIB>_STELA_FIXED_ENUMS_`.
- `STELA_EXTRACT` keeps its name. It's the extractor's command-line switch.
- A plain `<LIB>_STELA_H_` include guard replaces the template's version
  guard.

Outside the extractor every annotation expands to nothing, so the generated
file costs nothing at compile time. Each library's names carry its own prefix,
so any mix of libraries and Stela versions can meet in one translation unit.
Never edit a generated file; change the template or the configuration and
regenerate.

## Usage

```powershell
node tools\stela\src\stela.ts vendor            # write each library's <lib>_stela.h
node tools\stela\src\stela.ts vendor --check    # exit 1 if any file is missing or stale
```

Options: `--config <file>` (default `stela.config.json` in the current
directory) and `--template <file>` (default `include/stela.h`). Paths in the
configuration are relative to the configuration file.

Exit codes: 0 success, 1 out-of-date files, 2 usage or configuration errors.

## Configuration (`stela.config.json`)

```json
{
  "schema": "stela.config/1",
  "libraries": [
    {
      "name": "v8host",
      "prefix": "v8host",
      "macroPrefix": "V8HOST",
      "headers": ["src/public/v8host_client.h"],
      "stelaHeader": "src/public/v8host_stela.h"
    }
  ]
}
```

- `stelaHeader` defaults to `<macroPrefix in lowercase>_stela.h` next to the
  first header. An extension library sets it to `false` and uses its base
  library's file.
- `stelaNames` gives one annotation a longer name if it clashes with a library
  macro that can't change: `{ "DEPRECATED": "V8HOST_STELA_DEPRECATED" }`.
- `status` names the library's status type (default `<prefix>_status`).
- `targets`, `includeDirs`, `owns`, `defines`, `lint`, and `diff` are reserved
  for later stages and accepted now.

## Tests

```powershell
cd tools\stela
npm test            # node --test: unit, CLI, and compile-matrix tests
npm run typecheck   # needs `npm install` once
```

The compile matrix generates two libraries' files (one from a newer template
version) and compiles them alone and together, in both include orders:

- clang 9 language modes (C99–C23, C++11–C++23) × 6 targets (Windows x64,
  x86, ARM64, ARM64EC; Linux x64, ARM64), with
  `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wdocumentation -Werror`;
- MSVC 8 language modes × x64, x86, and ARM64, with `/W4 /WX`;
- before and after `<windows.h>`;
- extractor mode (`-DSTELA_EXTRACT`), where every annotation must reach the
  AST, and default mode, where none may.

Without Visual Studio the compile-matrix and extractor tests are skipped.

## License

MIT. Each generated file carries the same notice.
