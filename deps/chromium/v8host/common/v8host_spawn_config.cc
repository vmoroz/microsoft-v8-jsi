// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_spawn_config.h"

// The two spawn-time encodings. Both reuse the Contract B framing primitives
// (v8host::protocol::Writer/Reader) so every multi-byte integer is little-endian
// byte-by-byte and no raw bytes are cast onto a native struct. Exception-free:
// each decoder reports success through its return value and mutates no output on
// failure. The discipline mirrors the CREATE_SESSION / START_RUN codecs:
// {schema_version==1, fixed_size, total_size} header, forward-compat Skip to the
// variable section, strict UTF-8 / no-NUL strings, bounded counts, and exact
// consumption.

namespace v8host {

using protocol::Reader;
using protocol::Writer;

namespace {

// Decodes a wire boolean: exactly 0 or 1, anything else is malformed.
bool DecodeBool(uint32_t value, bool* out) {
  if (value > 1)
    return false;
  *out = (value != 0);
  return true;
}

// Reads the {schema_version==1, fixed_size, total_size} header shared by both
// encodings and enforces the framing invariants: total_size must equal the whole
// handed blob and stay within `max_size`, and fixed_size must cover the v1 known
// section yet fit inside total_size. On success the reader sits just past
// total_size.
bool ReadHeader(Reader& reader,
                size_t size,
                uint16_t schema_version,
                uint16_t known_fixed_size,
                uint32_t max_size,
                uint16_t* fixed_size) {
  uint16_t schema = 0;
  uint32_t total_size = 0;
  if (!reader.GetU16(&schema) || schema != schema_version)
    return false;
  if (!reader.GetU16(fixed_size))
    return false;
  if (!reader.GetU32(&total_size))
    return false;
  if (total_size != size)
    return false;  // declared length must match the actual blob exactly
  if (total_size > max_size)
    return false;  // per-encoding ceiling
  if (*fixed_size < known_fixed_size || *fixed_size > total_size)
    return false;
  return true;
}

// True iff `name` is a bare payload-directory filename: non-empty, no path
// separator or drive colon, and no ".." substring. Matches the sbox_config.cc
// allow_engine_dll setter exactly, so the codec is never the weaker validator of
// a directly-crafted worker/spawn blob.
bool IsBareFilename(const std::string& name) {
  if (name.empty() || name.find("..") != std::string::npos)
    return false;
  for (const char c : name) {
    if (c == '\\' || c == '/' || c == ':')
      return false;
  }
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// V8HostWorkerProfileV1
// ---------------------------------------------------------------------------
std::vector<uint8_t> V8HostWorkerProfileV1::Encode() const {
  Writer var;
  var.PutString(engine_dll);
  var.PutString(snapshot_path);

  const uint32_t total_size =
      kWorkerProfileFixedSize + static_cast<uint32_t>(var.size());

  Writer writer;
  writer.PutU16(kWorkerProfileSchemaVersion);
  writer.PutU16(kWorkerProfileFixedSize);
  writer.PutU32(total_size);
  writer.PutU32(jitless ? 1u : 0u);
  writer.PutBytes(var.buffer());
  return writer.buffer();
}

bool V8HostWorkerProfileV1::Decode(const uint8_t* data,
                                   size_t size,
                                   V8HostWorkerProfileV1* out) {
  Reader reader(data, size);
  V8HostWorkerProfileV1 p;

  uint16_t fixed_size = 0;
  if (!ReadHeader(reader, size, kWorkerProfileSchemaVersion,
                  kWorkerProfileFixedSize, kWorkerProfileMaxSize, &fixed_size))
    return false;

  uint32_t jitless_raw = 0;
  if (!reader.GetU32(&jitless_raw))
    return false;
  bool jitless_bool = false;
  if (!DecodeBool(jitless_raw, &jitless_bool))
    return false;
  p.jitless = jitless_bool ? 1u : 0u;

  // Forward-compat: skip any additive fixed fields a future minor version
  // appended, so the variable section starts exactly at fixed_size.
  if (!reader.Skip(fixed_size - kWorkerProfileFixedSize))
    return false;

  if (!reader.GetString(&p.engine_dll))
    return false;
  if (!reader.GetString(&p.snapshot_path))
    return false;

  // The engine DLL is a bare app-dir filename (never a path); the snapshot path
  // may be empty (no snapshot) or a payload-relative path the worker opens.
  if (!IsBareFilename(p.engine_dll))
    return false;

  if (!reader.AtEnd())
    return false;  // the body must be consumed exactly (ends at total_size)
  *out = std::move(p);
  return true;
}

// ---------------------------------------------------------------------------
// V8HostSpawnConfigV1
// ---------------------------------------------------------------------------
std::vector<uint8_t> V8HostSpawnConfigV1::Encode() const {
  // Encode the variable section first so total_size is known before the fixed
  // header is stamped. Encode trusts the caller's struct; the decoder is the
  // enforcement point for counts, booleans, strings, and cross-field rules.
  Writer var;
  var.PutString(app_container_profile);
  for (const V8HostSpawnFileRule& rule : file_rules) {
    var.PutU32(rule.readonly ? 1u : 0u);
    var.PutString(rule.pattern);
  }
  for (const std::string& capability : capabilities)
    var.PutString(capability);
  var.PutString(engine_dll);
  var.PutString(snapshot_path);

  const uint32_t total_size =
      kSpawnConfigFixedSize + static_cast<uint32_t>(var.size());

  Writer writer;
  writer.PutU16(kSpawnConfigSchemaVersion);
  writer.PutU16(kSpawnConfigFixedSize);
  writer.PutU32(total_size);
  writer.PutU32(static_cast<uint32_t>(tier));
  writer.PutU32(static_cast<uint32_t>(integrity));
  writer.PutU32(static_cast<uint32_t>(delayed_integrity));
  writer.PutU32(static_cast<uint32_t>(initial_token));
  writer.PutU32(static_cast<uint32_t>(lockdown_token));
  writer.PutU32(prohibit_dynamic_code ? 1u : 0u);
  writer.PutU32(use_app_container ? 1u : 0u);
  writer.PutU32(low_privilege_app_container ? 1u : 0u);
  writer.PutU32(static_cast<uint32_t>(effective_tier));
  writer.PutU32(static_cast<uint32_t>(file_rules.size()));
  writer.PutU32(static_cast<uint32_t>(capabilities.size()));
  writer.PutBytes(var.buffer());
  return writer.buffer();
}

bool V8HostSpawnConfigV1::Decode(const uint8_t* data,
                                 size_t size,
                                 V8HostSpawnConfigV1* out) {
  Reader reader(data, size);
  V8HostSpawnConfigV1 p;

  uint16_t fixed_size = 0;
  if (!ReadHeader(reader, size, kSpawnConfigSchemaVersion, kSpawnConfigFixedSize,
                  kSpawnConfigMaxSize, &fixed_size))
    return false;

  // Enum/token fields are transported as-is; the config builder validates them
  // against its allowlists (and poisons itself on a bad value).
  uint32_t scalars[5] = {};
  for (uint32_t& field : scalars) {
    if (!reader.GetU32(&field))
      return false;
  }
  p.tier = static_cast<int32_t>(scalars[0]);
  p.integrity = static_cast<int32_t>(scalars[1]);
  p.delayed_integrity = static_cast<int32_t>(scalars[2]);
  p.initial_token = static_cast<int32_t>(scalars[3]);
  p.lockdown_token = static_cast<int32_t>(scalars[4]);

  uint32_t prohibit = 0, use_ac = 0, lpac = 0, effective_tier = 0,
           file_rule_count = 0, capability_count = 0;
  if (!reader.GetU32(&prohibit) || !reader.GetU32(&use_ac) ||
      !reader.GetU32(&lpac) || !reader.GetU32(&effective_tier) ||
      !reader.GetU32(&file_rule_count) || !reader.GetU32(&capability_count))
    return false;
  if (!DecodeBool(prohibit, &p.prohibit_dynamic_code) ||
      !DecodeBool(use_ac, &p.use_app_container) ||
      !DecodeBool(lpac, &p.low_privilege_app_container))
    return false;
  p.effective_tier = static_cast<int32_t>(effective_tier);
  // Bound the counts before any length-keyed allocation.
  if (file_rule_count > protocol::kMaxFileRules ||
      capability_count > protocol::kMaxCapabilities)
    return false;

  // Forward-compat: skip any additive fixed fields to reach the variable
  // section, which starts at fixed_size.
  if (!reader.Skip(fixed_size - kSpawnConfigFixedSize))
    return false;

  if (!reader.GetString(&p.app_container_profile))
    return false;
  p.file_rules.resize(file_rule_count);
  for (V8HostSpawnFileRule& rule : p.file_rules) {
    uint32_t readonly = 0;
    if (!reader.GetU32(&readonly) || !DecodeBool(readonly, &rule.readonly))
      return false;
    if (!reader.GetString(&rule.pattern))
      return false;
  }
  p.capabilities.resize(capability_count);
  for (std::string& capability : p.capabilities) {
    if (!reader.GetString(&capability))
      return false;
  }
  if (!reader.GetString(&p.engine_dll))
    return false;
  if (!reader.GetString(&p.snapshot_path))
    return false;

  // Cross-field policy rules (design §8.5), fail-closed.
  if (p.app_container_profile.empty() && p.use_app_container)
    return false;  // an empty profile is legal only when AppContainer is off
  if (!p.capabilities.empty() && !p.use_app_container)
    return false;  // capabilities are legal only when AppContainer is on
  if (p.low_privilege_app_container && !p.use_app_container)
    return false;  // LPAC implies AppContainer
  // The effective engine is a bare app-dir filename (never a path); the snapshot
  // may be empty (no snapshot) or a payload-relative path the worker opens.
  if (!IsBareFilename(p.engine_dll))
    return false;

  if (!reader.AtEnd())
    return false;  // the body must be consumed exactly (ends at total_size)
  *out = std::move(p);
  return true;
}

}  // namespace v8host
