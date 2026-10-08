// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Deterministic, in-process conformance tests for the Stage 4 neutral
// run-envelope codec (:run_envelope): per-type round-trips, a canonical
// exact-byte vector (pins the layout cross-arch), magic detection, and the
// fail-closed decode rejections. Pure byte vectors — no pipes or spawned
// processes.

#include "v8host_test_support.h"  // brings in <windows.h> first

#include "v8host_run_envelope.h"  // transitive v8host_protocol.h #undefs ERROR

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using v8host::DecodeRunEnvelope;
using v8host::EncodeRunEnvelope;
using v8host::IsRunEnvelope;
using v8host::kRunEnvelopeMagic;
using v8host::RunEnvelope;
using v8host::RunEnvelopeDisposition;
using v8host::RunEnvelopeType;
using v8host::test::TestCase;

#define CHECK(cond, msg) \
  do {                   \
    if (!(cond)) {       \
      *detail = (msg);   \
      return false;      \
    }                    \
  } while (0)

std::vector<uint8_t> Bytes(std::initializer_list<uint8_t> b) {
  return std::vector<uint8_t>(b);
}

bool RoundTripStart(std::string* detail) {
  RunEnvelope in;
  in.type = RunEnvelopeType::kStart;
  in.run_id = 42;
  in.payload = Bytes({0x01, 0x02, 0x03, 0xFF});
  const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
  CHECK(IsRunEnvelope(enc.data(), enc.size()), "start: magic absent");
  RunEnvelope out;
  CHECK(DecodeRunEnvelope(enc.data(), enc.size(), &out), "start: decode");
  CHECK(out.type == RunEnvelopeType::kStart && out.run_id == 42 &&
            out.payload == in.payload,
        "start: field mismatch");
  // Empty guest payload also round-trips.
  RunEnvelope empty;
  empty.type = RunEnvelopeType::kStart;
  empty.run_id = 1;
  const std::vector<uint8_t> e2 = EncodeRunEnvelope(empty);
  RunEnvelope o2;
  CHECK(DecodeRunEnvelope(e2.data(), e2.size(), &o2) && o2.payload.empty() &&
            o2.run_id == 1,
        "start: empty payload");
  return true;
}

bool RoundTripRelay(std::string* detail) {
  RunEnvelope in;
  in.type = RunEnvelopeType::kRelay;
  in.run_id = 7;
  in.relay_kind = -5;  // signed kinds must survive
  in.payload = Bytes({0xAA, 0x00, 0xBB});
  const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
  RunEnvelope out;
  CHECK(DecodeRunEnvelope(enc.data(), enc.size(), &out), "relay: decode");
  CHECK(out.type == RunEnvelopeType::kRelay && out.run_id == 7 &&
            out.relay_kind == -5 && out.payload == in.payload,
        "relay: field mismatch");
  return true;
}

bool RoundTripCancel(std::string* detail) {
  RunEnvelope in;
  in.type = RunEnvelopeType::kCancel;
  in.run_id = 99;
  const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
  RunEnvelope out;
  CHECK(DecodeRunEnvelope(enc.data(), enc.size(), &out), "cancel: decode");
  CHECK(out.type == RunEnvelopeType::kCancel && out.run_id == 99,
        "cancel: field mismatch");
  return true;
}

bool RoundTripResult(std::string* detail) {
  for (const RunEnvelopeDisposition d :
       {RunEnvelopeDisposition::kCompleted, RunEnvelopeDisposition::kCancelled}) {
    RunEnvelope in;
    in.type = RunEnvelopeType::kResult;
    in.run_id = 3;
    in.disposition = d;
    const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
    RunEnvelope out;
    CHECK(DecodeRunEnvelope(enc.data(), enc.size(), &out) &&
              out.type == RunEnvelopeType::kResult && out.run_id == 3 &&
              out.disposition == d,
          "result: round-trip");
  }
  return true;
}

bool RoundTripRunError(std::string* detail) {
  RunEnvelope in;
  in.type = RunEnvelopeType::kRunError;
  in.run_id = 11;
  in.status_code = 0x1234;
  in.message = "boom (redacted)";
  const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
  RunEnvelope out;
  CHECK(DecodeRunEnvelope(enc.data(), enc.size(), &out), "run-error: decode");
  CHECK(out.type == RunEnvelopeType::kRunError && out.run_id == 11 &&
            out.status_code == 0x1234 && out.message == in.message,
        "run-error: field mismatch");
  // Empty message is legal.
  RunEnvelope empty;
  empty.type = RunEnvelopeType::kRunError;
  empty.status_code = 1;
  const std::vector<uint8_t> e2 = EncodeRunEnvelope(empty);
  RunEnvelope o2;
  CHECK(DecodeRunEnvelope(e2.data(), e2.size(), &o2) && o2.message.empty(),
        "run-error: empty message");
  return true;
}

bool DetectMagic(std::string* detail) {
  const RunEnvelope in{RunEnvelopeType::kCancel, 1, 0,
                       RunEnvelopeDisposition::kCompleted, 0, {}, {}};
  const std::vector<uint8_t> enc = EncodeRunEnvelope(in);
  CHECK(IsRunEnvelope(enc.data(), enc.size()), "detect: envelope not detected");
  // A bare dev-ambient relay (raw guest bytes) is not an envelope.
  const std::vector<uint8_t> bare = Bytes({'h', 'e', 'l', 'l', 'o'});
  CHECK(!IsRunEnvelope(bare.data(), bare.size()), "detect: bare misdetected");
  CHECK(!IsRunEnvelope(bare.data(), 3), "detect: short misdetected");
  CHECK(!IsRunEnvelope(nullptr, 0), "detect: null misdetected");
  return true;
}

bool CanonicalResultVector(std::string* detail) {
  // RESULT(kCancelled, run_id=7): magic "V8RE" | type 4 | reserved 0 | run 7 |
  // disposition 1 = exactly 16 bytes, identical on every arch.
  RunEnvelope in;
  in.type = RunEnvelopeType::kResult;
  in.run_id = 7;
  in.disposition = RunEnvelopeDisposition::kCancelled;
  const std::vector<uint8_t> want =
      Bytes({0x56, 0x38, 0x52, 0x45, 0x04, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
             0x00, 0x01, 0x00, 0x00, 0x00});
  const std::vector<uint8_t> got = EncodeRunEnvelope(in);
  CHECK(got == want, "result vector: bytes mismatch");
  return true;
}

bool RejectPaths(std::string* detail) {
  RunEnvelope out;
  // Bad magic.
  std::vector<uint8_t> bad = EncodeRunEnvelope(
      {RunEnvelopeType::kCancel, 1, 0, RunEnvelopeDisposition::kCompleted, 0, {},
       {}});
  bad[0] ^= 0xFF;
  CHECK(!DecodeRunEnvelope(bad.data(), bad.size(), &out), "bad magic accepted");
  // Unknown env_type (0 and 6).
  for (uint8_t t : {uint8_t{0}, uint8_t{6}}) {
    std::vector<uint8_t> f =
        Bytes({0x56, 0x38, 0x52, 0x45, t, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00});
    CHECK(!DecodeRunEnvelope(f.data(), f.size(), &out), "unknown type accepted");
  }
  // reserved != 0.
  std::vector<uint8_t> rsv =
      Bytes({0x56, 0x38, 0x52, 0x45, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
             0x00});
  CHECK(!DecodeRunEnvelope(rsv.data(), rsv.size(), &out), "reserved!=0 accepted");
  // RESULT with out-of-range disposition (2).
  std::vector<uint8_t> disp =
      Bytes({0x56, 0x38, 0x52, 0x45, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x02, 0x00, 0x00, 0x00});
  CHECK(!DecodeRunEnvelope(disp.data(), disp.size(), &out),
        "bad disposition accepted");
  // Trailing byte after a CANCEL body (must consume exactly).
  std::vector<uint8_t> trail =
      Bytes({0x56, 0x38, 0x52, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0xFF});
  CHECK(!DecodeRunEnvelope(trail.data(), trail.size(), &out),
        "trailing byte accepted");
  // Truncated header.
  std::vector<uint8_t> shortbuf = Bytes({0x56, 0x38, 0x52, 0x45, 0x03, 0x00});
  CHECK(!DecodeRunEnvelope(shortbuf.data(), shortbuf.size(), &out),
        "short header accepted");
  // RUN_ERROR with an embedded NUL in the message (strict UTF-8 / no NUL).
  std::vector<uint8_t> nul =
      Bytes({0x56, 0x38, 0x52, 0x45, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x41, 0x00});
  CHECK(!DecodeRunEnvelope(nul.data(), nul.size(), &out),
        "embedded NUL message accepted");
  CHECK(!DecodeRunEnvelope(nullptr, 0, &out), "null buffer accepted");
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<TestCase> tests = {
      {"roundtrip", "start", RoundTripStart},
      {"roundtrip", "relay", RoundTripRelay},
      {"roundtrip", "cancel", RoundTripCancel},
      {"roundtrip", "result", RoundTripResult},
      {"roundtrip", "run-error", RoundTripRunError},
      {"detect", "magic", DetectMagic},
      {"vector", "result-canonical", CanonicalResultVector},
      {"reject", "fail-closed-paths", RejectPaths},
  };
  return v8host::test::RunTests(argc, argv, tests);
}
