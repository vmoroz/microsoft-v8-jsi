import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** A v2 template: v1 plus one annotation, as a future Stela release would be. */
export function templateV2(v1: string): string {
  return v1
    .replace("(STELA_VERSION < 1)", "(STELA_VERSION < 2)")
    .replace("#define STELA_VERSION 1", "#define STELA_VERSION 2")
    .replace(
      "/* Tooling */",
      '/* Threads */\n#undef STELA_THREAD_ANY\n#define STELA_THREAD_ANY STELA_ANNOTATE_("thread=any")\n\n/* Tooling */',
    );
}

export function tempDir(t: { after(fn: () => void): void }, name: string): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), `stela-${name}-`));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
