// Public C ABI header gate (C ABI conventions §2 and §14). Each covered header
// must compile on its own, as C and as C++, with MSVC and with clang, warnings
// as errors, for every shipped architecture (x64, x86, arm64).
//
//   node --test scripts/header-check.ts
//   node --test --test-name-pattern=sbox scripts/header-check.ts
//
// clang runs freestanding with no system include paths, so a header can reach
// only <stddef.h>, <stdint.h>, <stdbool.h>, and its own library's headers;
// <wchar.h>, <windows.h>, and C++ headers fail. MSVC runs with the vcvars
// environment of each target architecture.
//
// A header that hasn't migrated to the conventions yet carries `pending`: its
// checks still run and report, as node:test `todo` tests, but don't fail the
// gate. Remove `pending` in the change that migrates the header.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import {
  type CompileJob,
  type CompileResult,
  type MsvcArch,
  type Toolchain,
  findToolchain,
  resolveOnPath,
  runJobs,
} from "../tools/stela/src/toolchain.ts";

interface Header {
  /** Repo-relative directory a consumer puts on its include path. */
  readonly root: string;
  /** The header as a consumer includes it, relative to `root`. */
  readonly include: string;
  /** Why the header doesn't pass yet, and which change fixes it. */
  readonly pending?: string;
}

// The include roots mirror the NuGet layout (scripts/build.ts): the jsi_abi
// headers are included as "jsi_abi/<file>" from the package's jsi folder.
const HEADERS: readonly Header[] = [
  { root: "deps/chromium/sandbox_dll", include: "sbox.h" },
  { root: "deps/chromium/sandbox_dll", include: "sbox_stela.h" },
  { root: "src/public", include: "v8host_client.h" },
  { root: "src/public", include: "v8host_stela.h" },
  { root: "src", include: "jsi_abi/jsi_abi.h" },
  { root: "src", include: "jsi_abi/jsi_abi_stela.h" },
  { root: "src", include: "jsi_abi/v8_jsi_abi.h" },
  { root: "src/node-api", include: "js_runtime_api.h" },
  { root: "src/node-api", include: "v8_api.h" },
];

const CLANG_WARNINGS = ["-Wall", "-Wextra", "-Wpedantic", "-Wdocumentation", "-Werror"];
const CLANG_TARGETS: Record<MsvcArch, string> = {
  x64: "x86_64-pc-windows-msvc",
  x86: "i686-pc-windows-msvc",
  arm64: "aarch64-pc-windows-msvc",
};
// The conventions' floors (C99, C++11) and the build's default (C17, C++17).
const CLANG_MODES = [
  ["c", "c99"],
  ["c", "c17"],
  ["c++", "c++11"],
  ["c++", "c++17"],
] as const;
// MSVC's oldest modes (C11, C++14) and the build's default (C17, C++17).
const MSVC_MODES = [
  ["c", "/std:c11"],
  ["c", "/std:c17"],
  ["c++", "/std:c++14"],
  ["c++", "/std:c++17"],
] as const;
const ARCHS: readonly MsvcArch[] = ["x64", "x86", "arm64"];
const COMPILERS = ["clang", "msvc"] as const;
type Compiler = (typeof COMPILERS)[number];

const repoRoot = path.resolve(import.meta.dirname, "..");

function jobsFor(
  tc: Toolchain,
  envs: Record<MsvcArch, NodeJS.ProcessEnv>,
  dir: string,
  header: Header,
  tu: string,
): Record<Compiler, CompileJob[]> {
  const root = path.join(repoRoot, header.root);
  const clang: CompileJob[] = [];
  const msvc: CompileJob[] = [];
  for (const arch of ARCHS) {
    for (const [lang, std] of CLANG_MODES) {
      clang.push({
        label: `clang ${arch} ${std}`,
        exe: tc.clang,
        args: [
          "-fsyntax-only",
          "-ffreestanding",
          "-nostdlibinc",
          `--target=${CLANG_TARGETS[arch]}`,
          "-x",
          lang,
          `-std=${std}`,
          ...CLANG_WARNINGS,
          "-fno-color-diagnostics",
          "-I",
          root,
          tu,
        ],
        cwd: dir,
      });
    }
    const env = envs[arch];
    for (const [lang, std] of MSVC_MODES) {
      const args = ["/nologo", "/Zs", "/W4", "/WX", lang === "c" ? "/TC" : "/TP", std];
      if (lang === "c++") args.push("/permissive-");
      args.push("/I", root, tu);
      msvc.push({ label: `cl ${arch} ${std}`, exe: resolveOnPath("cl.exe", env), args, cwd: dir, env });
    }
  }
  return { clang, msvc };
}

/** Groups failures by their first diagnostic so one broken line reads once. */
function report(results: readonly CompileResult[]): string {
  const failed = results.filter((r) => !r.ok);
  if (failed.length === 0) return "";
  const groups = new Map<string, CompileResult[]>();
  for (const r of failed) {
    const lines = r.output.trim().split(/\r?\n/);
    const key = lines.find((l) => /\berror\b/.test(l)) ?? lines[0] ?? "";
    const group = groups.get(key) ?? [];
    group.push(r);
    groups.set(key, group);
  }
  const parts = [`${failed.length} of ${results.length} compiles failed`];
  for (const group of groups.values()) {
    parts.push(`--- ${group.map((r) => r.job.label).join(", ")}`);
    parts.push(...group[0].output.trim().split(/\r?\n/).slice(0, 8));
  }
  return parts.join("\n");
}

describe("public C ABI headers compile standalone", () => {
  let dir = "";
  let setupError: string | undefined;
  const results = new Map<string, CompileResult[]>();
  const key = (header: Header, compiler: Compiler) => `${header.include} ${compiler}`;

  before(async () => {
    const tc = await findToolchain();
    if (typeof tc === "string") {
      setupError = tc;
      return;
    }
    dir = mkdtempSync(path.join(os.tmpdir(), "header-check-"));
    const envs = {} as Record<MsvcArch, NodeJS.ProcessEnv>;
    for (const arch of ARCHS) envs[arch] = await tc.msvcEnv(arch);
    const all: { key: string; job: CompileJob }[] = [];
    HEADERS.forEach((header, index) => {
      // Including the header twice also checks its include guard. The typedef
      // keeps a macro-only header's C translation unit from being empty.
      const tu = `tu${index}.c`;
      writeFileSync(
        path.join(dir, tu),
        `#include "${header.include}"\n#include "${header.include}"\ntypedef int header_check_nonempty;\n`,
      );
      const jobs = jobsFor(tc, envs, dir, header, tu);
      for (const compiler of COMPILERS) {
        for (const job of jobs[compiler]) all.push({ key: key(header, compiler), job });
      }
    });
    const done = await runJobs(all.map((j) => j.job));
    done.forEach((result, i) => {
      const list = results.get(all[i].key) ?? [];
      list.push(result);
      results.set(all[i].key, list);
    });
  });

  after(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  for (const header of HEADERS) {
    for (const compiler of COMPILERS) {
      test(`${header.include} (${compiler})`, { todo: header.pending ?? false }, () => {
        assert.equal(setupError, undefined, `toolchain: ${setupError}`);
        const list = results.get(key(header, compiler)) ?? [];
        assert.ok(list.length > 0, "no compile jobs ran");
        const failures = report(list);
        if (failures) assert.fail(failures);
      });
    }
  }
});
