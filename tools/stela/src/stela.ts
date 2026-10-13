#!/usr/bin/env node
// The Stela CLI. Run with Node.js 24+: node tools/stela/src/stela.ts <command>.
// Exit codes: 0 success; 1 check failures; 2 usage or tool errors.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { loadConfig } from "./config.ts";
import { StelaError } from "./errors.ts";
import { extractModel } from "./extract.ts";
import { GENERATORS, generate } from "./generators.ts";
import { formatFindings, lintModel } from "./lint.ts";
import { defaultModelPath, formatMismatch, readModel, serializeModel } from "./model.ts";
import { generateLibraryHeader, normalizeText, parseTemplate } from "./vendor.ts";

export const DEFAULT_TEMPLATE = path.join(import.meta.dirname, "..", "include", "stela.h");

const USAGE = `usage: node stela.ts <command> [options]

commands:
  vendor   generate each library's <lib>_stela.h from the stela.h template
             --config <file>    default: stela.config.json
             --template <file>  default: tools/stela/include/stela.h
             --check            report out-of-date files instead of writing
  extract  extract every library for every target and merge stela.model/1
             --config <file>    default: stela.config.json
             --out <file>       default: out/stela/<config name>.model.json
  lint     check a stela.model/1 against the C ABI conventions
             --config <file>    default: stela.config.json
             --model <file>     default: the extract default for --config
             --format <format>  text (default) or json
             --report-only      report errors without failing
  gen      <generator> --out <dir>   generators: ${GENERATORS.join(", ")}
             --model <file>     default: the extract default for --config
             --config <file>    default: stela.config.json

exit codes: 0 success; 1 check failures (stale files, target mismatches);
            2 usage or tool errors
`;

interface Io {
  out(line: string): void;
  err(line: string): void;
}

function display(root: string, file: string): string {
  return path.relative(root, file).split(path.sep).join("/");
}

function vendor(argv: string[], io: Io): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: "string", default: "stela.config.json" },
      template: { type: "string", default: DEFAULT_TEMPLATE },
      check: { type: "boolean", default: false },
    },
    strict: true,
    allowPositionals: false,
  });
  const config = loadConfig(values.config as string);
  let templateText: string;
  try {
    templateText = readFileSync(values.template as string, "utf8");
  } catch (e) {
    throw new StelaError(`cannot read template ${values.template}: ${(e as Error).message}`);
  }
  const template = parseTemplate(templateText);

  let stale = 0;
  for (const lib of config.libraries) {
    if (lib.stelaHeader === false) continue;
    const file = lib.stelaHeader;
    const text = generateLibraryHeader(template, {
      macroPrefix: lib.macroPrefix,
      fileName: path.basename(file),
      stelaNames: lib.stelaNames,
    });
    const existing = existsSync(file) ? readFileSync(file) : undefined;
    const shown = display(config.root, file);
    if (values.check) {
      // Compare text, so a CRLF checkout of an up-to-date file still passes.
      if (existing === undefined) {
        io.err(`missing:   ${shown}`);
        stale++;
      } else if (normalizeText(existing.toString("utf8")) !== text) {
        io.err(`stale:     ${shown}`);
        stale++;
      } else {
        io.out(`current:   ${shown}`);
      }
    } else if (existing !== undefined && existing.equals(Buffer.from(text, "utf8"))) {
      io.out(`unchanged: ${shown}`);
    } else {
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, text, "utf8");
      io.out(`wrote:     ${shown}`);
    }
  }
  if (stale > 0) {
    io.err(`${stale} generated file(s) are out of date; run \`stela vendor\``);
    return 1;
  }
  return 0;
}

/** Writes `text` only when the bytes differ; replaces an existing file atomically. */
function writeIfChanged(file: string, text: string): "wrote" | "unchanged" {
  const bytes = Buffer.from(text, "utf8");
  if (existsSync(file) && readFileSync(file).equals(bytes)) return "unchanged";
  mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  writeFileSync(temp, bytes);
  renameSync(temp, file);
  return "wrote";
}

async function extract(argv: string[], io: Io): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: "string", default: "stela.config.json" },
      out: { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });
  const config = loadConfig(values.config as string);
  const out = path.resolve(values.out ?? defaultModelPath(config.file));
  const { model, mismatches } = await extractModel(config);
  if (mismatches.length > 0) {
    for (const m of mismatches) io.err(formatMismatch(m));
    io.err(`${mismatches.length} declaration(s) differ between targets; no model written`);
    return 1;
  }
  const status = writeIfChanged(out, serializeModel(model));
  const count = model.libraries.reduce((n, l) => n + l.declarations.length, 0);
  io.out(
    `${`${status}:`.padEnd(11)}${display(process.cwd(), out)} ` +
      `(${model.libraries.length} libraries, ${model.targets.length} targets, ${count} declarations)`,
  );
  return 0;
}

function gen(argv: string[], io: Io): number {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      model: { type: "string" },
      config: { type: "string", default: "stela.config.json" },
      out: { type: "string" },
    },
    strict: true,
    allowPositionals: true,
  });
  if (positionals.length !== 1) throw new StelaError(`gen takes one generator: ${GENERATORS.join(", ")}`);
  if (values.out === undefined) throw new StelaError("gen needs --out <dir>");
  const modelFile = values.model ?? defaultModelPath(values.config as string);
  const files = generate(positionals[0], readModel(modelFile));
  const outDir = path.resolve(values.out);
  for (const file of files) {
    const target = path.join(outDir, ...file.path.split("/"));
    const status = writeIfChanged(target, file.text);
    io.out(`${`${status}:`.padEnd(11)}${display(process.cwd(), target)}`);
  }
  return 0;
}

function lint(argv: string[], io: Io): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      model: { type: "string" },
      config: { type: "string", default: "stela.config.json" },
      format: { type: "string", default: "text" },
      "report-only": { type: "boolean", default: false },
    },
    strict: true,
    allowPositionals: false,
  });
  if (values.format !== "text" && values.format !== "json") {
    throw new StelaError('lint --format must be "text" or "json"');
  }
  const config = loadConfig(values.config as string);
  const modelFile = path.resolve(values.model ?? defaultModelPath(config.file));
  const findings = lintModel(readModel(modelFile), config);
  const text = formatFindings(findings, values.format);
  if (text !== "") io.out(text);
  if (values.format === "text") {
    const counts = { error: 0, warning: 0, info: 0 };
    for (const finding of findings) counts[finding.severity]++;
    io.out(
      `${findings.length} finding(s): ${counts.error} error(s), ` +
        `${counts.warning} warning(s), ${counts.info} info`,
    );
  }
  return values["report-only"] || !findings.some((f) => f.severity === "error") ? 0 : 1;
}

export async function main(argv: string[], io: Io): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case "vendor":
        return vendor(rest, io);
      case "extract":
        return await extract(rest, io);
      case "lint":
        return lint(rest, io);
      case "gen":
        return gen(rest, io);
      case undefined:
      case "help":
      case "--help":
      case "-h":
        io.out(USAGE);
        return command === undefined ? 2 : 0;
      default:
        io.err(`unknown command "${command}"\n${USAGE}`);
        return 2;
    }
  } catch (e) {
    if (e instanceof StelaError || (e as { code?: string }).code?.startsWith("ERR_PARSE_ARGS")) {
      io.err(`stela: ${(e as Error).message}`);
      return 2;
    }
    throw e;
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2), {
    out: (line) => process.stdout.write(line + "\n"),
    err: (line) => process.stderr.write(line + "\n"),
  });
}
