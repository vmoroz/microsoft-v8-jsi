// Loads and validates stela.config.json (Stela design §8.2). Only the keys
// that the implemented commands need are interpreted; the rest of the §8.2
// schema is accepted so the file can grow ahead of the tool.

import { readFileSync } from "node:fs";
import path from "node:path";
import { StelaError } from "./errors.ts";

export const CONFIG_SCHEMA = "stela.config/1";

export interface LibraryConfig {
  readonly name: string;
  readonly prefix: string;
  readonly macroPrefix: string;
  /** Entry headers, absolute paths. */
  readonly headers: readonly string[];
  /** Absolute path of the generated <lib>_stela.h, or false for an extension library. */
  readonly stelaHeader: string | false;
  readonly stelaNames: Readonly<Record<string, string>>;
  /** The library's status type (§8.2 `status`). */
  readonly status: string;
}

export interface StelaConfig {
  /** Absolute path of the config file. */
  readonly file: string;
  /** The directory that config paths are relative to. */
  readonly root: string;
  readonly libraries: readonly LibraryConfig[];
}

const TOP_LEVEL_KEYS = new Set(["$schema", "schema", "targets", "libraries", "lint", "diff"]);
const LIBRARY_KEYS = new Set([
  "name",
  "prefix",
  "macroPrefix",
  "headers",
  "includeDirs",
  "owns",
  "defines",
  "targets",
  "status",
  "stelaHeader",
  "stelaNames",
]);
const LOWER_SNAKE_RE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const UPPER_SNAKE_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringList(value: unknown, where: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string" && v !== "")) {
    throw new StelaError(`${where} must be an array of non-empty strings`);
  }
  return value as string[];
}

export function parseConfig(json: unknown, file: string): StelaConfig {
  const root = path.dirname(path.resolve(file));
  if (!isObject(json)) throw new StelaError(`${file}: the config must be a JSON object`);
  for (const key of Object.keys(json)) {
    if (!TOP_LEVEL_KEYS.has(key)) throw new StelaError(`${file}: unknown key "${key}"`);
  }
  if (json.schema !== CONFIG_SCHEMA) {
    throw new StelaError(`${file}: "schema" must be "${CONFIG_SCHEMA}"`);
  }
  if (!Array.isArray(json.libraries) || json.libraries.length === 0) {
    throw new StelaError(`${file}: "libraries" must be a non-empty array`);
  }

  const libraries: LibraryConfig[] = [];
  const names = new Set<string>();
  const macroPrefixes = new Map<string, string>();
  const outputs = new Map<string, string>();
  json.libraries.forEach((raw: unknown, index: number) => {
    const where = `${file}: libraries[${index}]`;
    if (!isObject(raw)) throw new StelaError(`${where} must be an object`);
    for (const key of Object.keys(raw)) {
      if (!LIBRARY_KEYS.has(key)) throw new StelaError(`${where}: unknown key "${key}"`);
    }
    const { name, prefix, macroPrefix } = raw;
    if (typeof name !== "string" || !LOWER_SNAKE_RE.test(name)) {
      throw new StelaError(`${where}: "name" must be lowercase_snake`);
    }
    if (names.has(name)) throw new StelaError(`${where}: duplicate library name "${name}"`);
    names.add(name);
    if (typeof prefix !== "string" || !LOWER_SNAKE_RE.test(prefix)) {
      throw new StelaError(`${where}: "prefix" must be lowercase_snake`);
    }
    if (typeof macroPrefix !== "string" || !UPPER_SNAKE_RE.test(macroPrefix)) {
      throw new StelaError(`${where}: "macroPrefix" must be UPPER_SNAKE`);
    }
    const headers = stringList(raw.headers, `${where}: "headers"`).map((h) =>
      path.resolve(root, h),
    );

    let stelaHeader: string | false;
    if (raw.stelaHeader === false) {
      stelaHeader = false;
    } else if (raw.stelaHeader === undefined) {
      if (headers.length === 0) {
        throw new StelaError(`${where}: set "stelaHeader" or list at least one header`);
      }
      stelaHeader = path.join(path.dirname(headers[0]), `${macroPrefix.toLowerCase()}_stela.h`);
    } else if (typeof raw.stelaHeader === "string" && raw.stelaHeader.endsWith(".h")) {
      stelaHeader = path.resolve(root, raw.stelaHeader);
    } else {
      throw new StelaError(`${where}: "stelaHeader" must be a .h path or false`);
    }
    if (stelaHeader !== false) {
      // Two libraries may share a status type, but never a generated file or
      // its macro namespace.
      const otherFile = outputs.get(stelaHeader.toLowerCase());
      if (otherFile) {
        throw new StelaError(`${where}: "stelaHeader" is also written by "${otherFile}"`);
      }
      outputs.set(stelaHeader.toLowerCase(), name);
      const otherPrefix = macroPrefixes.get(macroPrefix);
      if (otherPrefix) {
        throw new StelaError(`${where}: macroPrefix "${macroPrefix}" is also used by "${otherPrefix}"`);
      }
      macroPrefixes.set(macroPrefix, name);
    }

    let stelaNames: Record<string, string> = {};
    if (raw.stelaNames !== undefined) {
      if (!isObject(raw.stelaNames) || !Object.values(raw.stelaNames).every((v) => typeof v === "string")) {
        throw new StelaError(`${where}: "stelaNames" must map names to strings`);
      }
      if (stelaHeader === false) {
        throw new StelaError(`${where}: "stelaNames" needs a generated "stelaHeader"`);
      }
      stelaNames = raw.stelaNames as Record<string, string>;
    }

    const status = raw.status ?? `${prefix}_status`;
    if (typeof status !== "string" || !LOWER_SNAKE_RE.test(status)) {
      throw new StelaError(`${where}: "status" must be a lowercase_snake type name`);
    }
    libraries.push({ name, prefix, macroPrefix, headers, stelaHeader, stelaNames, status });
  });
  return { file: path.resolve(file), root, libraries };
}

export function loadConfig(file: string): StelaConfig {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    throw new StelaError(`cannot read ${file}: ${(e as Error).message}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text.replace(/^\uFEFF/, ""));
  } catch (e) {
    throw new StelaError(`${file}: invalid JSON: ${(e as Error).message}`);
  }
  return parseConfig(json, file);
}
