# Stela

Stela checks C ABI headers. It currently provides the annotation vocabulary,
the native extractor, `stela vendor`, the merged `stela.model/1`, and the
header-test and layout-test generators. Later stages add lint rules, ABI diff,
more generators, and manifests embedded in binaries. It incubates here with no
dependency on v8-jsi code, so it can move to its own repository unchanged.

Status: stage S3, the CLI, the model, and the test generators.

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
node tools\stela\src\stela.ts extract           # write out\stela\stela.model.json
node tools\stela\src\stela.ts gen layout-tests --out out\stela\tests
```

Options: `--config <file>` (default `stela.config.json` in the current
directory), `--template <file>` (`vendor`; default `include/stela.h`),
`--out <file>` (`extract`; default `out/stela/<config name>.model.json` next to
the configuration), and `--model <file>` (`gen`; default the `extract`
output). Paths in the configuration are relative to the configuration file.
Every command writes a file only when its content changes.

Exit codes: 0 success; 1 check failures (out-of-date files, a declaration that
differs between targets); 2 usage, configuration, or tool errors.

## The model (`stela.model/1`)

`stela extract` runs the extractor for every library on each of its targets,
in parallel, and merges the results. Facts that must agree on every target
(types, fields, enumerators, documentation, annotations) appear once; sizes,
alignments, offsets, and enumerator values go under `perTarget`. A declaration
missing on some targets lists the ones it has in `targets`. Any other
difference between targets is an error: `extract` prints the first differing
path for each declaration, exits 1, and writes nothing.

Declarations keep source order. Keys have a fixed order and the JSON is
compact (a container that fits in 100 columns stays on one line), so the same
headers always give the same bytes. Opaque records carry `incomplete: true`
and no layout; a record defined without a tag carries `tagless: true`. A field
whose type has neither a tag nor a typedef name (`union { … } data;`) carries
that type inline, as `{"union": {"fields": [...]}}`, so no absolute path from
Clang's spelling reaches the model.
[`schema/stela.model.schema.json`](schema/stela.model.schema.json) describes
the format.

## Generators

`stela gen <generator> --out <dir>` writes one directory per library:

- `header-tests`: `<header>.header.c` and `.cpp` per entry header. Each
  defines the library's defines and includes its header alone, twice, to check
  the include guard.
- `layout-tests`: `layout.c` and `layout.cpp`. Static asserts of each record's
  size, alignment, and field offsets (except bit-fields and anonymous members),
  each object typedef's size and alignment, and each enumerator's value. Layout
  checks are grouped by target under the compiler's architecture macros.

Both compile with clang (`-ffreestanding -nostdlibinc`, warnings as errors)
and MSVC (`/W4 /WX`) for each target, as C and C++. Header tests keep the
C99 floor; layout tests need C11 for `_Static_assert`. v8-jsi runs the layout
tests in `scripts/header-check.ts`.

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
- `targets` (top level) lists every target the model covers, as clang
  triples; a library's own `targets` narrows it to a subset, in the same
  order.
- `includeDirs` lists include directories as a consumer sets them (the
  generated tests spell each `#include` relative to the first one that holds
  the header); `owns` lists the files or directories whose declarations belong
  to the library (default: the entry headers); `defines` are `NAME` or
  `NAME=VALUE`.
- `lint` and `diff` are reserved for later stages and accepted now.
- [`schema/stela.config.schema.json`](schema/stela.config.schema.json)
  describes the format.

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
