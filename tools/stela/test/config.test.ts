import assert from "node:assert/strict";
import path from "node:path";
import { test } from "node:test";
import { parseConfig } from "../src/config.ts";
import { StelaError } from "../src/errors.ts";

const file = path.resolve("/repo/stela.config.json");
const root = path.dirname(file);
const lib = (extra: Record<string, unknown> = {}) => ({
  name: "v8host",
  prefix: "v8host",
  macroPrefix: "V8HOST",
  headers: ["src/public/v8host_client.h"],
  ...extra,
});
const parse = (libraries: unknown[], top: Record<string, unknown> = {}) =>
  parseConfig({ schema: "stela.config/1", libraries, ...top }, file);

test("defaults: stelaHeader next to the first header, status from the prefix", () => {
  const [l] = parse([lib()]).libraries;
  assert.equal(l.stelaHeader, path.join(root, "src", "public", "v8host_stela.h"));
  assert.equal(l.status, "v8host_status");
  assert.deepEqual(l.stelaNames, {});
  assert.deepEqual(l.headers, [path.join(root, "src", "public", "v8host_client.h")]);
});

test("explicit stelaHeader, extension libraries, and other §8.2 keys", () => {
  const config = parse(
    [
      lib({ stelaHeader: "include/v8host_stela.h", includeDirs: ["src/public"], targets: ["x86_64-pc-windows-msvc"] }),
      { name: "jsi_abi", prefix: "jsi", macroPrefix: "JSI_ABI", stelaHeader: "src/jsi_abi/jsi_abi_stela.h" },
      { name: "v8_jsi_abi", prefix: "v8_jsi_abi", macroPrefix: "V8_JSI_ABI", headers: ["a.h"], stelaHeader: false, status: "jsi_status" },
    ],
    { targets: [], lint: {}, diff: {} },
  );
  assert.equal(config.libraries[0].stelaHeader, path.join(root, "include", "v8host_stela.h"));
  assert.equal(config.libraries[1].stelaHeader, path.join(root, "src", "jsi_abi", "jsi_abi_stela.h"));
  assert.equal(config.libraries[2].stelaHeader, false);
  assert.equal(config.libraries[2].status, "jsi_status");
});

test("invalid configs are rejected", () => {
  const bad = (libraries: unknown[], top: Record<string, unknown> = {}) =>
    assert.throws(() => parse(libraries, top), StelaError);
  assert.throws(() => parseConfig({ libraries: [lib()] }, file), StelaError);
  assert.throws(() => parseConfig([], file), StelaError);
  bad([]);
  bad([lib()], { typo: 1 });
  bad([lib({ typo: 1 })]);
  bad([lib({ name: "V8Host" })]);
  bad([lib({ prefix: "V8HOST" })]);
  bad([lib({ macroPrefix: "v8host" })]);
  bad([lib(), lib({ macroPrefix: "OTHER" })]);
  bad([lib(), lib({ name: "other" })]);
  bad([lib(), lib({ name: "other", macroPrefix: "OTHER", stelaHeader: "src/public/v8host_stela.h" })]);
  bad([lib({ headers: undefined })]);
  bad([lib({ headers: [""] })]);
  bad([lib({ stelaHeader: "x.txt" })]);
  bad([lib({ stelaHeader: true })]);
  bad([lib({ stelaHeader: false, stelaNames: { ENUM: "V8HOST_STELA_ENUM" } })]);
  bad([lib({ stelaNames: { ENUM: 1 } })]);
  bad([lib({ status: "Status" })]);
});
