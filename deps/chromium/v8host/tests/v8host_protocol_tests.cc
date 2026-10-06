// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Deterministic, in-process conformance tests for the Contract B framing core
// (v8host_protocol). No processes, pipes, or Windows calls — only byte vectors.
// The `vectors` suite asserts exact bytes for canonical encodings, which is the
// real cross-arch guarantee; `--vectors-only` additionally prints a SHA-256 over
// all canonical vectors so CI can compare x86/x64/arm64 digests.

#include "v8host_test_support.h"  // brings in <windows.h>; must precede the header
#include "v8host_protocol.h"      // its #undef ERROR neutralizes the wingdi macro
#include "v8host_protocol_messages.h"  // message codecs, negotiation, request cache

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <string>
#include <vector>

namespace {

using namespace v8host::protocol;
using v8host::test::TestCase;

// ---------------------------------------------------------------------------
// Self-contained SHA-256 (FIPS 180-4). Lives only in this test TU so the
// protocol static_library stays dependency-free. Operates on raw bytes.
// ---------------------------------------------------------------------------
class Sha256 {
 public:
  Sha256() { Reset(); }

  void Reset() {
    state_[0] = 0x6a09e667; state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372; state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f; state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab; state_[7] = 0x5be0cd19;
    bitlen_ = 0;
    buflen_ = 0;
  }

  void Update(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
      buffer_[buflen_++] = data[i];
      if (buflen_ == 64) {
        Transform();
        bitlen_ += 512;
        buflen_ = 0;
      }
    }
  }

  void Final(uint8_t out[32]) {
    const uint64_t total_bits = bitlen_ + static_cast<uint64_t>(buflen_) * 8;
    buffer_[buflen_++] = 0x80;
    if (buflen_ > 56) {
      while (buflen_ < 64)
        buffer_[buflen_++] = 0x00;
      Transform();
      buflen_ = 0;
    }
    while (buflen_ < 56)
      buffer_[buflen_++] = 0x00;
    for (int i = 7; i >= 0; --i)
      buffer_[buflen_++] = static_cast<uint8_t>((total_bits >> (i * 8)) & 0xFF);
    Transform();
    for (int i = 0; i < 8; ++i) {
      out[i * 4 + 0] = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
      out[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
      out[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xFF);
      out[i * 4 + 3] = static_cast<uint8_t>(state_[i] & 0xFF);
    }
  }

 private:
  static uint32_t Rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
  }

  void Transform() {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t m[64];
    for (int i = 0; i < 16; ++i) {
      m[i] = (static_cast<uint32_t>(buffer_[i * 4 + 0]) << 24) |
             (static_cast<uint32_t>(buffer_[i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(buffer_[i * 4 + 2]) << 8) |
             (static_cast<uint32_t>(buffer_[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
      const uint32_t s0 =
          Rotr(m[i - 15], 7) ^ Rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
      const uint32_t s1 =
          Rotr(m[i - 2], 17) ^ Rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
      m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
      const uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t t1 = h + s1 + ch + K[i] + m[i];
      const uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t t2 = s0 + maj;
      h = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  uint32_t state_[8];
  uint8_t buffer_[64];
  uint64_t bitlen_;
  size_t buflen_;
};

std::string Sha256Hex(const uint8_t* data, size_t size) {
  Sha256 sha;
  sha.Update(data, size);
  uint8_t digest[32];
  sha.Final(digest);
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (int i = 0; i < 32; ++i) {
    out.push_back(kHex[(digest[i] >> 4) & 0xF]);
    out.push_back(kHex[digest[i] & 0xF]);
  }
  return out;
}

std::string Sha256Hex(const std::vector<uint8_t>& v) {
  return Sha256Hex(v.data(), v.size());
}

std::string Sha256HexStr(const char* s) {
  return Sha256Hex(reinterpret_cast<const uint8_t*>(s), std::strlen(s));
}

// ---------------------------------------------------------------------------
// Small test helpers.
// ---------------------------------------------------------------------------
bool Fail(std::string* detail, const std::string& message) {
  *detail = message;
  return false;
}

bool CheckBytes(const char* label,
                const std::vector<uint8_t>& got,
                const uint8_t* want,
                size_t want_len,
                std::string* detail) {
  if (got.size() != want_len) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "%s: size %zu != %zu", label, got.size(),
                  want_len);
    return Fail(detail, buf);
  }
  for (size_t i = 0; i < want_len; ++i) {
    if (got[i] != want[i]) {
      char buf[128];
      std::snprintf(buf, sizeof(buf), "%s: byte[%zu] = 0x%02X != 0x%02X", label,
                    i, got[i], want[i]);
      return Fail(detail, buf);
    }
  }
  return true;
}

FrameHeader Sentinel() {
  FrameHeader h;
  h.version_major = 0xAAAA;
  h.version_minor = 0xBBBB;
  h.type = static_cast<MessageType>(0xCCCC);
  h.flags = 0xDDDD;
  h.conn_id = 0x11111111;
  h.session_id = 0x22222222;
  h.run_id = 0x33333333;
  h.request_id = 0x44444444;
  h.payload_length = 0x55555555;
  return h;
}

bool SameHeader(const FrameHeader& a, const FrameHeader& b) {
  return a.version_major == b.version_major &&
         a.version_minor == b.version_minor && a.type == b.type &&
         a.flags == b.flags && a.conn_id == b.conn_id &&
         a.session_id == b.session_id && a.run_id == b.run_id &&
         a.request_id == b.request_id && a.payload_length == b.payload_length;
}

// A framing-valid frame with the given payload length (flags within the mask).
std::vector<uint8_t> SampleFrame(uint32_t payload_len) {
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.type = MessageType::START_RUN;
  h.flags = kFlagMustUnderstand;
  h.conn_id = 0x01020304;
  h.session_id = 0x05060708;
  h.run_id = 0x090A0B0C;
  h.request_id = 0x0D0E0F10;
  h.payload_length = payload_len;
  std::vector<uint8_t> out;
  EncodeHeader(h, out);
  for (uint32_t i = 0; i < payload_len; ++i)
    out.push_back(static_cast<uint8_t>(i & 0xFF));
  return out;
}

// A string field: u32 length prefix (`len_field`, which may intentionally
// disagree with `bytes` to exercise the length checks) followed by `bytes`.
std::vector<uint8_t> StrBuf(uint32_t len_field,
                            std::initializer_list<uint8_t> bytes) {
  Writer w;
  w.PutU32(len_field);
  std::vector<uint8_t> out = w.buffer();
  out.insert(out.end(), bytes.begin(), bytes.end());
  return out;
}

// ---------------------------------------------------------------------------
// Canonical vectors (fixed order; concatenated for the SHA-256 digest).
// ---------------------------------------------------------------------------

// V1: every header field a distinct, byte-identifiable value (layout probe).
std::vector<uint8_t> VectorAllDistinctHeader() {
  FrameHeader h;
  h.version_major = 0x0102;
  h.version_minor = 0x0304;
  h.type = MessageType::RELAY_FROM_WORKER;  // 0x0201
  h.flags = kFlagMustUnderstand;            // 0x0001
  h.conn_id = 0x11223344;
  h.session_id = 0x55667788;
  h.run_id = 0x99AABBCC;
  h.request_id = 0xDDEEFF00;
  h.payload_length = 0x0000000A;
  std::vector<uint8_t> out;
  EncodeHeader(h, out);
  return out;
}

// V2: a HELLO-shaped header (zero conn/session/run, nonzero request id).
std::vector<uint8_t> VectorHelloHeader() {
  FrameHeader h;
  h.version_major = kWireVersionMajor;  // 1
  h.version_minor = kWireVersionMinor;  // 0
  h.type = MessageType::HELLO;          // 0x0001
  h.flags = 0;
  h.conn_id = 0;
  h.session_id = 0;
  h.run_id = 0;
  h.request_id = 1;
  h.payload_length = 0;
  std::vector<uint8_t> out;
  EncodeHeader(h, out);
  return out;
}

// V3: a Writer payload exercising PutU16/PutU32/PutString (string "A" + U+20AC).
std::vector<uint8_t> VectorWriterPayload() {
  Writer w;
  w.PutU16(0xABCD);
  w.PutU32(0x12345678);
  w.PutString("A\xE2\x82\xAC");
  return w.buffer();
}

// V4: a full CREATE_SESSION frame — header (payload_length set) + the V3 payload.
std::vector<uint8_t> VectorFullFrame() {
  const std::vector<uint8_t> payload = VectorWriterPayload();
  FrameHeader h;
  h.version_major = kWireVersionMajor;
  h.version_minor = kWireVersionMinor;
  h.type = MessageType::CREATE_SESSION;  // 0x0003
  h.flags = 0;
  h.conn_id = 7;
  h.session_id = 0;
  h.run_id = 0;
  h.request_id = 0x0000002A;
  h.payload_length = static_cast<uint32_t>(payload.size());
  std::vector<uint8_t> out;
  EncodeHeader(h, out);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

// V5: a HELLO frame (client -> broker); schema-only payload, nonzero request id.
std::vector<uint8_t> VectorHelloFrame() {
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.request_id = 1;  // conn/session/run stay 0 by contract
  return BuildHelloFrame(h);
}

// V6: a HELLO_ACK frame (broker -> client) carrying the frozen limits.
std::vector<uint8_t> VectorHelloAckFrame() {
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.conn_id = 9;     // the assigned connection id
  h.request_id = 1;  // echoes the HELLO
  HelloAckPayload p;
  p.broker_version_major = 1;
  p.broker_version_minor = 0;
  p.endpoint_mode = kEndpointModeShared;
  p.max_frame_payload = kMaxFramePayload;
  p.max_sessions_per_connection = kMaxSessionsPerConnection;
  p.max_in_flight_runs_per_session = kMaxInFlightRunsPerSession;
  p.max_file_rules = kMaxFileRules;
  p.max_capabilities = kMaxCapabilities;
  p.max_queued_relay_bytes_per_run = kMaxQueuedRelayBytesPerRun;
  p.max_queued_relay_bytes_per_connection = kMaxQueuedRelayBytesPerConnection;
  return BuildHelloAckFrame(h, p);
}

// V7: an ACK frame (broker -> client) echoing session/run/request correlation.
std::vector<uint8_t> VectorAckFrame() {
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.conn_id = 9;
  h.session_id = 2;
  h.run_id = 3;
  h.request_id = 0x2A;
  return BuildAckFrame(h);
}

// V8: an ERROR frame (broker -> client); status ERROR_QUOTA + a short message.
std::vector<uint8_t> VectorErrorFrame() {
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.conn_id = 9;
  h.session_id = 2;
  h.run_id = 3;
  h.request_id = 0x2B;
  ErrorPayload p;
  p.status_code = StatusCode::ERROR_QUOTA;
  p.message = "quota";
  return BuildErrorFrame(h, p);
}

std::vector<std::vector<uint8_t>> CanonicalVectors() {
  return {VectorAllDistinctHeader(), VectorHelloHeader(), VectorWriterPayload(),
          VectorFullFrame(),         VectorHelloFrame(),  VectorHelloAckFrame(),
          VectorAckFrame(),          VectorErrorFrame()};
}

std::vector<uint8_t> CanonicalConcat() {
  std::vector<uint8_t> all;
  for (const std::vector<uint8_t>& v : CanonicalVectors())
    all.insert(all.end(), v.begin(), v.end());
  return all;
}

// Hard-coded expected bytes (computed independently). These exact-byte asserts
// are the cross-arch contract: any arch must produce precisely these bytes.
const uint8_t kExpectAllDistinct[32] = {
    0x56, 0x38, 0x48, 0x57, 0x02, 0x01, 0x04, 0x03, 0x01, 0x02, 0x01,
    0x00, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xCC, 0xBB,
    0xAA, 0x99, 0x00, 0xFF, 0xEE, 0xDD, 0x0A, 0x00, 0x00, 0x00};

const uint8_t kExpectHello[32] = {
    0x56, 0x38, 0x48, 0x57, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const uint8_t kExpectWriterPayload[14] = {0xCD, 0xAB, 0x78, 0x56, 0x34, 0x12,
                                          0x04, 0x00, 0x00, 0x00, 0x41, 0xE2,
                                          0x82, 0xAC};

// Slice (b) message frames. Exact bytes computed independently; any arch must
// produce precisely these for the HELLO / HELLO_ACK / ACK / ERROR layers.
const uint8_t kExpectHelloFrame[36] = {
    0x56, 0x38, 0x48, 0x57, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

const uint8_t kExpectHelloAckFrame[72] = {
    0x56, 0x38, 0x48, 0x57, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xF8, 0xFF, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01};

const uint8_t kExpectAckFrame[36] = {
    0x56, 0x38, 0x48, 0x57, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x2A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

const uint8_t kExpectErrorFrame[49] = {
    0x56, 0x38, 0x48, 0x57, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x2B, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x71, 0x75, 0x6F, 0x74,
    0x61};

// ---------------------------------------------------------------------------
// vectors suite.
// ---------------------------------------------------------------------------
bool CanonicalAllDistinctHeader(std::string* detail) {
  return CheckBytes("all-distinct", VectorAllDistinctHeader(), kExpectAllDistinct,
                    sizeof(kExpectAllDistinct), detail);
}

bool CanonicalHelloHeader(std::string* detail) {
  return CheckBytes("hello", VectorHelloHeader(), kExpectHello,
                    sizeof(kExpectHello), detail);
}

bool CanonicalWriterPayload(std::string* detail) {
  return CheckBytes("writer-payload", VectorWriterPayload(), kExpectWriterPayload,
                    sizeof(kExpectWriterPayload), detail);
}

bool FullFrameRoundTrip(std::string* detail) {
  const std::vector<uint8_t> frame = VectorFullFrame();
  FrameHeader out;
  const uint8_t* payload = nullptr;
  size_t payload_size = 0;
  const DecodeStatus st = DecodeAndValidateFrame(frame.data(), frame.size(),
                                                 &out, &payload, &payload_size);
  if (st != DecodeStatus::kOk)
    return Fail(detail, "decode failed");
  if (out.version_major != 1 || out.version_minor != 0)
    return Fail(detail, "version mismatch");
  if (out.type != MessageType::CREATE_SESSION)
    return Fail(detail, "type mismatch");
  if (out.conn_id != 7 || out.session_id != 0 || out.run_id != 0 ||
      out.request_id != 0x0000002A)
    return Fail(detail, "id mismatch");
  const std::vector<uint8_t> expected = VectorWriterPayload();
  if (payload_size != expected.size())
    return Fail(detail, "payload size mismatch");
  if (payload == nullptr || std::memcmp(payload, expected.data(), payload_size) != 0)
    return Fail(detail, "payload bytes mismatch");
  return true;
}

bool CanonicalHelloFrame(std::string* detail) {
  return CheckBytes("hello-frame", VectorHelloFrame(), kExpectHelloFrame,
                    sizeof(kExpectHelloFrame), detail);
}

bool CanonicalHelloAckFrame(std::string* detail) {
  return CheckBytes("hello-ack-frame", VectorHelloAckFrame(),
                    kExpectHelloAckFrame, sizeof(kExpectHelloAckFrame), detail);
}

bool CanonicalAckFrame(std::string* detail) {
  return CheckBytes("ack-frame", VectorAckFrame(), kExpectAckFrame,
                    sizeof(kExpectAckFrame), detail);
}

bool CanonicalErrorFrame(std::string* detail) {
  return CheckBytes("error-frame", VectorErrorFrame(), kExpectErrorFrame,
                    sizeof(kExpectErrorFrame), detail);
}

// ---------------------------------------------------------------------------
// protocol suite.
// ---------------------------------------------------------------------------
bool Sha256SelfTest(std::string* detail) {
  if (Sha256HexStr("") !=
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    return Fail(detail, "sha256(empty) mismatch");
  if (Sha256HexStr("abc") !=
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    return Fail(detail, "sha256(abc) mismatch");
  // 56-byte input forces the two-block padding path.
  if (Sha256HexStr(
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") !=
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    return Fail(detail, "sha256(56-byte) mismatch");
  return true;
}

bool HeaderRoundTrip(std::string* detail) {
  const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x7F};
  FrameHeader in;
  in.version_major = 1;
  in.version_minor = 0;
  in.type = MessageType::RESULT;
  in.flags = kFlagMustUnderstand;
  in.conn_id = 0x11223344;
  in.session_id = 0x55667788;
  in.run_id = 0x99AABBCC;
  in.request_id = 0xDDEEFF00;
  in.payload_length = static_cast<uint32_t>(payload.size());
  std::vector<uint8_t> frame;
  EncodeHeader(in, frame);
  frame.insert(frame.end(), payload.begin(), payload.end());

  FrameHeader out = Sentinel();
  const uint8_t* view = nullptr;
  size_t view_size = 0;
  if (DecodeAndValidateFrame(frame.data(), frame.size(), &out, &view,
                             &view_size) != DecodeStatus::kOk)
    return Fail(detail, "decode failed");
  if (!SameHeader(in, out))
    return Fail(detail, "header fields differ");
  if (view_size != payload.size() || view == nullptr ||
      std::memcmp(view, payload.data(), view_size) != 0)
    return Fail(detail, "payload view mismatch");
  return true;
}

bool MagicReject(std::string* detail) {
  std::vector<uint8_t> frame = SampleFrame(0);
  frame[0] ^= 0xFF;  // corrupt the magic
  FrameHeader out = Sentinel();
  if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
      DecodeStatus::kBadMagic)
    return Fail(detail, "bad magic not rejected");
  if (!SameHeader(out, Sentinel()))
    return Fail(detail, "output mutated on failure");
  return true;
}

bool TruncationEveryPrefix(std::string* detail) {
  const std::vector<uint8_t> frames[] = {SampleFrame(0), SampleFrame(6)};
  for (const std::vector<uint8_t>& frame : frames) {
    for (size_t prefix = 0; prefix < frame.size(); ++prefix) {
      FrameHeader out = Sentinel();
      const DecodeStatus st =
          DecodeAndValidateFrame(frame.data(), prefix, &out);
      // Below a full header the decode stops at the header-size check; at or
      // above it the header decodes but the declared size no longer matches.
      const DecodeStatus expected = prefix < kFrameHeaderSize
                                        ? DecodeStatus::kIncompleteHeader
                                        : DecodeStatus::kLengthMismatch;
      if (st != expected) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "prefix %zu/%zu status %u != %u", prefix,
                      frame.size(), static_cast<unsigned>(st),
                      static_cast<unsigned>(expected));
        return Fail(detail, buf);
      }
      if (!SameHeader(out, Sentinel())) {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "prefix %zu mutated output", prefix);
        return Fail(detail, buf);
      }
    }
  }
  return true;
}

bool PayloadLengthBounds(std::string* detail) {
  // payload_length == kMaxFramePayload, size == 32 + 65528 -> ok.
  {
    FrameHeader h;
    h.version_major = 1;
    h.type = MessageType::RELAY_TO_WORKER;
    h.payload_length = kMaxFramePayload;
    std::vector<uint8_t> frame;
    EncodeHeader(h, frame);
    frame.resize(kFrameHeaderSize + kMaxFramePayload, 0xAB);
    FrameHeader out;
    size_t payload_size = 0;
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out, nullptr,
                               &payload_size) != DecodeStatus::kOk)
      return Fail(detail, "max payload rejected");
    if (payload_size != kMaxFramePayload)
      return Fail(detail, "max payload size wrong");
  }
  // payload_length == kMaxFramePayload + 1 (65529) -> reject (oversize).
  {
    FrameHeader h;
    h.version_major = 1;
    h.type = MessageType::RELAY_TO_WORKER;
    h.payload_length = kMaxFramePayload + 1;
    std::vector<uint8_t> frame;
    EncodeHeader(h, frame);
    frame.resize(kFrameHeaderSize + kMaxFramePayload + 1, 0xAB);
    FrameHeader out = Sentinel();
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
        DecodeStatus::kOversizePayload)
      return Fail(detail, "max+1 payload not rejected");
    if (!SameHeader(out, Sentinel()))
      return Fail(detail, "max+1 mutated output");
  }
  // payload_length that would overflow 32 + len is caught by the oversize gate
  // before any addition — a 32-byte buffer claiming a 4 GiB payload.
  {
    FrameHeader h;
    h.version_major = 1;
    h.type = MessageType::RELAY_TO_WORKER;
    h.payload_length = 0xFFFFFFFFu;
    std::vector<uint8_t> frame;
    EncodeHeader(h, frame);
    FrameHeader out = Sentinel();
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
        DecodeStatus::kOversizePayload)
      return Fail(detail, "overflow-length not rejected");
    if (!SameHeader(out, Sentinel()))
      return Fail(detail, "overflow-length mutated output");
  }
  return true;
}

bool ExactFrame(std::string* detail) {
  std::vector<uint8_t> frame = SampleFrame(8);  // 40 bytes, payload_length == 8
  frame.push_back(0x99);                         // 41 bytes with an extra tail
  FrameHeader out = Sentinel();
  if (DecodeAndValidateFrame(frame.data(), 39, &out) !=
      DecodeStatus::kLengthMismatch)
    return Fail(detail, "size-1 not rejected");
  if (!SameHeader(out, Sentinel()))
    return Fail(detail, "size-1 mutated output");
  FrameHeader ok;
  if (DecodeAndValidateFrame(frame.data(), 40, &ok) != DecodeStatus::kOk)
    return Fail(detail, "exact size rejected");
  out = Sentinel();
  if (DecodeAndValidateFrame(frame.data(), 41, &out) !=
      DecodeStatus::kLengthMismatch)
    return Fail(detail, "size+1 not rejected");
  if (!SameHeader(out, Sentinel()))
    return Fail(detail, "size+1 mutated output");
  // A zero-payload frame (exactly 32 bytes) with one trailing byte is likewise
  // not one declared frame.
  {
    std::vector<uint8_t> empty = SampleFrame(0);  // 32 bytes, payload_length 0
    empty.push_back(0x5A);                         // 33 bytes
    FrameHeader bad = Sentinel();
    if (DecodeAndValidateFrame(empty.data(), 33, &bad) !=
        DecodeStatus::kLengthMismatch)
      return Fail(detail, "zero-payload size+1 not rejected");
    if (!SameHeader(bad, Sentinel()))
      return Fail(detail, "zero-payload size+1 mutated output");
    FrameHeader good;
    if (DecodeAndValidateFrame(empty.data(), 32, &good) != DecodeStatus::kOk)
      return Fail(detail, "zero-payload exact size rejected");
  }
  return true;
}

bool ReservedFlags(std::string* detail) {
  const uint16_t reserved_values[] = {0x0002, 0x8000, 0xFFFE};
  for (uint16_t flags : reserved_values) {
    FrameHeader h;
    h.version_major = 1;
    h.type = MessageType::HELLO;
    h.flags = flags;
    h.payload_length = 0;
    std::vector<uint8_t> frame;
    EncodeHeader(h, frame);
    FrameHeader out = Sentinel();
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
        DecodeStatus::kReservedFlags)
      return Fail(detail, "reserved flag not rejected");
    if (!SameHeader(out, Sentinel()))
      return Fail(detail, "reserved flag mutated output");
  }
  // MUST_UNDERSTAND alone is framing-valid.
  {
    FrameHeader h;
    h.version_major = 1;
    h.type = MessageType::HELLO;
    h.flags = kFlagMustUnderstand;
    h.payload_length = 0;
    std::vector<uint8_t> frame;
    EncodeHeader(h, frame);
    FrameHeader out;
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
        DecodeStatus::kOk)
      return Fail(detail, "must-understand rejected");
    if (out.flags != kFlagMustUnderstand)
      return Fail(detail, "flags not preserved");
  }
  return true;
}

bool ReaderBounds(std::string* detail) {
  const uint8_t buf[3] = {0x01, 0x02, 0x03};
  {
    Reader r(buf, sizeof(buf));
    uint16_t v = 0;
    if (!r.GetU16(&v) || v != 0x0201)
      return Fail(detail, "GetU16 LE wrong");
    uint16_t v2 = 0;
    if (r.GetU16(&v2))
      return Fail(detail, "GetU16 past end accepted");
    if (r.offset() != 2 || r.BytesRemaining() != 1)
      return Fail(detail, "GetU16 mutated on failure");
  }
  {
    Reader r(buf, sizeof(buf));
    uint32_t v = 0;
    if (r.GetU32(&v))
      return Fail(detail, "GetU32 past end accepted");
    if (r.offset() != 0)
      return Fail(detail, "GetU32 mutated on failure");
  }
  {
    Reader r(buf, sizeof(buf));
    std::vector<uint8_t> out;
    if (r.GetBytes(4, &out))
      return Fail(detail, "GetBytes past end accepted");
    if (r.offset() != 0)
      return Fail(detail, "GetBytes mutated on failure");
    if (!r.GetBytes(3, &out) || out.size() != 3 || out[0] != 1 || out[2] != 3)
      return Fail(detail, "GetBytes exact failed");
    if (!r.AtEnd())
      return Fail(detail, "reader not at end");
  }
  return true;
}

bool WriterReaderRoundTrip(std::string* detail) {
  Writer w;
  w.PutU16(0xBEEF);
  w.PutU32(0x01234567);
  const std::vector<uint8_t> raw = {0xAA, 0xBB, 0xCC};
  w.PutBytes(raw);
  const std::string text = "hello \xE2\x82\xAC world";
  w.PutString(text);

  Reader r(w.buffer());
  uint16_t a = 0;
  uint32_t b = 0;
  std::vector<uint8_t> c;
  std::string s;
  if (!r.GetU16(&a) || a != 0xBEEF)
    return Fail(detail, "u16 round-trip");
  if (!r.GetU32(&b) || b != 0x01234567)
    return Fail(detail, "u32 round-trip");
  if (!r.GetBytes(raw.size(), &c) || c != raw)
    return Fail(detail, "bytes round-trip");
  if (!r.GetString(&s) || s != text)
    return Fail(detail, "string round-trip");
  if (!r.AtEnd())
    return Fail(detail, "reader not fully consumed");
  return true;
}

bool StringReaderValid(std::string* detail) {
  Writer w;
  w.PutString("A\xE2\x82\xAC");
  Reader r(w.buffer());
  std::string s;
  if (!r.GetString(&s))
    return Fail(detail, "valid string rejected");
  if (s.size() != 4 || static_cast<uint8_t>(s[0]) != 0x41 ||
      static_cast<uint8_t>(s[1]) != 0xE2 ||
      static_cast<uint8_t>(s[2]) != 0x82 ||
      static_cast<uint8_t>(s[3]) != 0xAC)
    return Fail(detail, "string bytes wrong");
  if (!r.AtEnd())
    return Fail(detail, "reader not at end");
  // Round-trip each UTF-8 length class at its boundary code points: U+0080 and
  // U+07FF (2-byte), U+0800 and U+FFFF (3-byte), U+10000 and U+10FFFF (4-byte).
  {
    const std::vector<uint8_t> bytes = {
        0xC2, 0x80,              // U+0080
        0xDF, 0xBF,              // U+07FF
        0xE0, 0xA0, 0x80,        // U+0800
        0xEF, 0xBF, 0xBF,        // U+FFFF
        0xF0, 0x90, 0x80, 0x80,  // U+10000
        0xF4, 0x8F, 0xBF, 0xBF,  // U+10FFFF
    };
    const std::string boundaries(bytes.begin(), bytes.end());
    Writer bw;
    bw.PutString(boundaries);
    Reader br(bw.buffer());
    std::string got;
    if (!br.GetString(&got) || got != boundaries)
      return Fail(detail, "boundary code points round-trip failed");
    if (!br.AtEnd())
      return Fail(detail, "boundary reader not at end");
  }
  return true;
}

bool StringReaderReject(std::string* detail) {
  struct Case {
    const char* name;
    std::vector<uint8_t> buf;
  };
  const Case cases[] = {
      {"len>remaining", StrBuf(100, {0x41, 0x42, 0x43})},
      {"len>max", StrBuf(kMaxStringBytes + 1, {})},
      {"embedded-nul", StrBuf(3, {0x41, 0x00, 0x42})},
      {"overlong-c0-80", StrBuf(2, {0xC0, 0x80})},
      {"overlong-e0-80-80", StrBuf(3, {0xE0, 0x80, 0x80})},
      {"overlong-f0-80-80-80", StrBuf(4, {0xF0, 0x80, 0x80, 0x80})},
      {"lone-80", StrBuf(1, {0x80})},
      {"truncated-c2", StrBuf(1, {0xC2})},
      {"truncated-e2-82", StrBuf(2, {0xE2, 0x82})},
      {"surrogate-ed-a0-80", StrBuf(3, {0xED, 0xA0, 0x80})},
      {"surrogate-ed-bf-bf", StrBuf(3, {0xED, 0xBF, 0xBF})},
      {"above-10ffff-f4-90", StrBuf(4, {0xF4, 0x90, 0x80, 0x80})},
      {"above-10ffff-f5", StrBuf(4, {0xF5, 0x80, 0x80, 0x80})},
  };
  for (const Case& c : cases) {
    Reader r(c.buf);
    std::string s = "UNTOUCHED";
    if (r.GetString(&s))
      return Fail(detail, std::string("accepted invalid: ") + c.name);
    if (r.offset() != 0)
      return Fail(detail, std::string("mutated on reject: ") + c.name);
    if (s != "UNTOUCHED")
      return Fail(detail, std::string("out param written on reject: ") + c.name);
  }
  // A valid non-empty string still passes next to these rejects.
  {
    Writer w;
    w.PutString("ok");
    Reader r(w.buffer());
    std::string s;
    if (!r.GetString(&s) || s != "ok")
      return Fail(detail, "valid string after rejects failed");
  }
  return true;
}

// ---------------------------------------------------------------------------
// messages suite: payload codec round-trips, reject paths, builders.
// ---------------------------------------------------------------------------
std::vector<uint8_t> ValidHelloBytes() {
  Writer w;
  EncodeHelloPayload(HelloPayload{}, w);
  return w.buffer();
}

std::vector<uint8_t> ValidHelloAckBytes() {
  Writer w;
  EncodeHelloAckPayload(HelloAckPayload{}, w);
  return w.buffer();
}

std::vector<uint8_t> ValidAckBytes() {
  Writer w;
  EncodeAckPayload(AckPayload{}, w);
  return w.buffer();
}

std::vector<uint8_t> ValidErrorBytes() {
  ErrorPayload p;
  p.status_code = StatusCode::ERROR_PROTOCOL;
  p.message = "x";
  Writer w;
  EncodeErrorPayload(p, w);
  return w.buffer();
}

bool MessagesHelloRoundTrip(std::string* detail) {
  const std::vector<uint8_t> bytes = ValidHelloBytes();
  HelloPayload out;
  out.schema_version = 0xFFFF;  // sentinels; decode must overwrite
  out.reserved = 0xFFFF;
  if (!DecodeHelloPayload(bytes.data(), bytes.size(), &out))
    return Fail(detail, "hello decode failed");
  if (out.schema_version != kMessageSchemaVersion || out.reserved != 0)
    return Fail(detail, "hello fields wrong");
  return true;
}

bool MessagesHelloAckRoundTrip(std::string* detail) {
  HelloAckPayload in;
  in.broker_version_major = 0x1234;
  in.broker_version_minor = 0x5678;
  in.endpoint_mode = kEndpointModeDedicated;
  in.max_frame_payload = 0x00010203;
  in.max_sessions_per_connection = 0x04050607;
  in.max_in_flight_runs_per_session = 0x08090A0B;
  in.max_file_rules = 0x0C0D0E0F;
  in.max_capabilities = 0x10111213;
  in.max_queued_relay_bytes_per_run = 0x14151617;
  in.max_queued_relay_bytes_per_connection = 0x18191A1B;
  Writer w;
  EncodeHelloAckPayload(in, w);
  HelloAckPayload out;
  if (!DecodeHelloAckPayload(w.buffer().data(), w.buffer().size(), &out))
    return Fail(detail, "hello-ack decode failed");
  if (out.schema_version != kMessageSchemaVersion || out.reserved != 0 ||
      out.broker_version_major != in.broker_version_major ||
      out.broker_version_minor != in.broker_version_minor ||
      out.endpoint_mode != in.endpoint_mode ||
      out.max_frame_payload != in.max_frame_payload ||
      out.max_sessions_per_connection != in.max_sessions_per_connection ||
      out.max_in_flight_runs_per_session != in.max_in_flight_runs_per_session ||
      out.max_file_rules != in.max_file_rules ||
      out.max_capabilities != in.max_capabilities ||
      out.max_queued_relay_bytes_per_run != in.max_queued_relay_bytes_per_run ||
      out.max_queued_relay_bytes_per_connection !=
          in.max_queued_relay_bytes_per_connection)
    return Fail(detail, "hello-ack fields differ");
  return true;
}

bool MessagesAckRoundTrip(std::string* detail) {
  const std::vector<uint8_t> bytes = ValidAckBytes();
  AckPayload out;
  out.schema_version = 0xFFFF;
  out.reserved = 0xFFFF;
  if (!DecodeAckPayload(bytes.data(), bytes.size(), &out))
    return Fail(detail, "ack decode failed");
  if (out.schema_version != kMessageSchemaVersion || out.reserved != 0)
    return Fail(detail, "ack fields wrong");
  return true;
}

bool MessagesErrorRoundTrip(std::string* detail) {
  // Non-empty message carrying a multi-byte code point.
  {
    ErrorPayload in;
    in.status_code = StatusCode::ERROR_STALE_REQUEST;
    in.message = "stale \xE2\x82\xAC";
    Writer w;
    EncodeErrorPayload(in, w);
    ErrorPayload out;
    if (!DecodeErrorPayload(w.buffer().data(), w.buffer().size(), &out))
      return Fail(detail, "error decode failed");
    if (out.schema_version != kMessageSchemaVersion || out.reserved != 0 ||
        out.status_code != StatusCode::ERROR_STALE_REQUEST ||
        out.message != in.message)
      return Fail(detail, "error fields differ");
  }
  // Empty message.
  {
    ErrorPayload in;
    in.status_code = StatusCode::ERROR_QUOTA;
    in.message = "";
    Writer w;
    EncodeErrorPayload(in, w);
    ErrorPayload out;
    out.message = "UNTOUCHED";
    if (!DecodeErrorPayload(w.buffer().data(), w.buffer().size(), &out))
      return Fail(detail, "empty-message error decode failed");
    if (out.status_code != StatusCode::ERROR_QUOTA || !out.message.empty())
      return Fail(detail, "empty-message error fields differ");
  }
  return true;
}

bool MessagesRejectBadPrologue(std::string* detail) {
  // A bad schema_version or reserved value is rejected before any other field;
  // a 4-byte prologue alone is enough to prove the check fires for every type.
  const std::vector<uint8_t> bad_schema = {0x02, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> bad_reserved = {0x01, 0x00, 0x01, 0x00};
  struct Decoder {
    const char* name;
    std::function<bool(const uint8_t*, size_t)> fn;
  };
  const Decoder decoders[] = {
      {"hello",
       [](const uint8_t* d, size_t n) {
         HelloPayload o;
         return DecodeHelloPayload(d, n, &o);
       }},
      {"hello-ack",
       [](const uint8_t* d, size_t n) {
         HelloAckPayload o;
         return DecodeHelloAckPayload(d, n, &o);
       }},
      {"ack",
       [](const uint8_t* d, size_t n) {
         AckPayload o;
         return DecodeAckPayload(d, n, &o);
       }},
      {"error",
       [](const uint8_t* d, size_t n) {
         ErrorPayload o;
         return DecodeErrorPayload(d, n, &o);
       }},
  };
  for (const Decoder& dec : decoders) {
    if (dec.fn(bad_schema.data(), bad_schema.size()))
      return Fail(detail, std::string("bad schema accepted: ") + dec.name);
    if (dec.fn(bad_reserved.data(), bad_reserved.size()))
      return Fail(detail, std::string("bad reserved accepted: ") + dec.name);
  }
  return true;
}

bool MessagesRejectFraming(std::string* detail) {
  // Trailing bytes (payload not fully consumed) and truncation at every prefix
  // are rejected for each payload type.
  struct Case {
    const char* name;
    std::vector<uint8_t> valid;
    std::function<bool(const uint8_t*, size_t)> fn;
  };
  const Case cases[] = {
      {"hello", ValidHelloBytes(),
       [](const uint8_t* d, size_t n) {
         HelloPayload o;
         return DecodeHelloPayload(d, n, &o);
       }},
      {"hello-ack", ValidHelloAckBytes(),
       [](const uint8_t* d, size_t n) {
         HelloAckPayload o;
         return DecodeHelloAckPayload(d, n, &o);
       }},
      {"ack", ValidAckBytes(),
       [](const uint8_t* d, size_t n) {
         AckPayload o;
         return DecodeAckPayload(d, n, &o);
       }},
      {"error", ValidErrorBytes(),
       [](const uint8_t* d, size_t n) {
         ErrorPayload o;
         return DecodeErrorPayload(d, n, &o);
       }},
  };
  for (const Case& c : cases) {
    if (!c.fn(c.valid.data(), c.valid.size()))
      return Fail(detail, std::string("valid rejected: ") + c.name);
    std::vector<uint8_t> extra = c.valid;
    extra.push_back(0x00);
    if (c.fn(extra.data(), extra.size()))
      return Fail(detail, std::string("trailing accepted: ") + c.name);
    for (size_t n = 0; n < c.valid.size(); ++n) {
      if (c.fn(c.valid.data(), n))
        return Fail(detail, std::string("truncation accepted: ") + c.name);
    }
  }
  return true;
}

bool MessagesRejectErrorString(std::string* detail) {
  // Prologue (schema=1, reserved=0) + status_code, then a malformed string.
  auto build = [](const std::vector<uint8_t>& str_field) {
    Writer w;
    w.PutU16(1);
    w.PutU16(0);
    w.PutU32(1);
    std::vector<uint8_t> out = w.buffer();
    out.insert(out.end(), str_field.begin(), str_field.end());
    return out;
  };
  // Embedded NUL in the message bytes.
  {
    const std::vector<uint8_t> field = {0x03, 0x00, 0x00, 0x00,
                                        0x41, 0x00, 0x42};
    const std::vector<uint8_t> bytes = build(field);
    ErrorPayload out;
    if (DecodeErrorPayload(bytes.data(), bytes.size(), &out))
      return Fail(detail, "embedded NUL accepted");
  }
  // Invalid UTF-8 (lone continuation byte).
  {
    const std::vector<uint8_t> field = {0x01, 0x00, 0x00, 0x00, 0x80};
    const std::vector<uint8_t> bytes = build(field);
    ErrorPayload out;
    if (DecodeErrorPayload(bytes.data(), bytes.size(), &out))
      return Fail(detail, "invalid UTF-8 accepted");
  }
  return true;
}

bool MessagesBuildersStampType(std::string* detail) {
  // Each builder owns the message type and produces a frame that decodes back
  // to that type, regardless of a caller-set header.type.
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.request_id = 1;
  h.type = MessageType::RESULT;  // deliberately wrong; must be overwritten
  HelloAckPayload ack_payload;
  ErrorPayload err_payload;
  err_payload.message = "x";
  struct Case {
    MessageType want;
    std::vector<uint8_t> frame;
  };
  const Case cases[] = {
      {MessageType::HELLO, BuildHelloFrame(h)},
      {MessageType::HELLO_ACK, BuildHelloAckFrame(h, ack_payload)},
      {MessageType::ACK, BuildAckFrame(h)},
      {MessageType::ERROR, BuildErrorFrame(h, err_payload)},
  };
  for (const Case& c : cases) {
    FrameHeader out;
    if (DecodeAndValidateFrame(c.frame.data(), c.frame.size(), &out) !=
        DecodeStatus::kOk)
      return Fail(detail, "builder frame decode failed");
    if (out.type != c.want)
      return Fail(detail, "builder did not stamp the type");
    if (out.request_id != 1)
      return Fail(detail, "builder dropped correlation");
  }
  return true;
}

bool MessagesCorrelation(std::string* detail) {
  // ACK/ERROR builders echo conn/session/run/request in the frame header.
  FrameHeader h;
  h.version_major = 1;
  h.version_minor = 0;
  h.conn_id = 0x0A0B0C0D;
  h.session_id = 0x11223344;
  h.run_id = 0x55667788;
  h.request_id = 0x99AABBCC;
  auto check = [&](const std::vector<uint8_t>& frame, MessageType want) {
    FrameHeader out;
    if (DecodeAndValidateFrame(frame.data(), frame.size(), &out) !=
        DecodeStatus::kOk)
      return false;
    return out.type == want && out.conn_id == h.conn_id &&
           out.session_id == h.session_id && out.run_id == h.run_id &&
           out.request_id == h.request_id;
  };
  if (!check(BuildAckFrame(h), MessageType::ACK))
    return Fail(detail, "ack correlation not echoed");
  ErrorPayload p;
  p.status_code = StatusCode::ERROR_BAD_STATE;
  p.message = "x";
  if (!check(BuildErrorFrame(h, p), MessageType::ERROR))
    return Fail(detail, "error correlation not echoed");
  return true;
}

// ---------------------------------------------------------------------------
// negotiate suite: version matrix (E15).
// ---------------------------------------------------------------------------
NegotiationResult RunNegotiate(uint16_t client_major,
                               uint16_t client_minor,
                               uint16_t broker_major,
                               uint16_t broker_minor,
                               uint32_t conn_id,
                               uint32_t request_id) {
  FrameHeader hello;
  hello.version_major = client_major;
  hello.version_minor = client_minor;
  hello.type = MessageType::HELLO;
  hello.request_id = request_id;
  BrokerCapabilities caps;
  caps.broker_version_major = broker_major;
  caps.broker_version_minor = broker_minor;
  return NegotiateHello(hello, HelloPayload{}, caps, conn_id);
}

bool CheckHelloAck(const NegotiationResult& r,
                   uint16_t expect_selected_minor,
                   uint16_t expect_broker_minor,
                   uint32_t expect_conn,
                   uint32_t expect_request,
                   std::string* detail) {
  if (r.decision != NegotiationDecision::kAck)
    return Fail(detail, "decision not kAck");
  if (r.selected_minor != expect_selected_minor)
    return Fail(detail, "selected_minor wrong");
  FrameHeader out;
  const uint8_t* pl = nullptr;
  size_t pls = 0;
  if (DecodeAndValidateFrame(r.frame.data(), r.frame.size(), &out, &pl, &pls) !=
      DecodeStatus::kOk)
    return Fail(detail, "hello-ack frame decode failed");
  if (out.type != MessageType::HELLO_ACK)
    return Fail(detail, "reply not HELLO_ACK");
  if (out.conn_id != expect_conn)
    return Fail(detail, "assigned conn id not in header");
  if (out.request_id != expect_request)
    return Fail(detail, "request id not echoed");
  if (out.version_major != 1 || out.version_minor != expect_selected_minor)
    return Fail(detail, "header wire version wrong");
  HelloAckPayload p;
  if (!DecodeHelloAckPayload(pl, pls, &p))
    return Fail(detail, "hello-ack payload decode failed");
  if (p.broker_version_major != 1 ||
      p.broker_version_minor != expect_broker_minor)
    return Fail(detail, "broker max version wrong");
  if (p.endpoint_mode != kEndpointModeShared ||
      p.max_frame_payload != kMaxFramePayload ||
      p.max_sessions_per_connection != kMaxSessionsPerConnection ||
      p.max_in_flight_runs_per_session != kMaxInFlightRunsPerSession ||
      p.max_file_rules != kMaxFileRules ||
      p.max_capabilities != kMaxCapabilities ||
      p.max_queued_relay_bytes_per_run != kMaxQueuedRelayBytesPerRun ||
      p.max_queued_relay_bytes_per_connection !=
          kMaxQueuedRelayBytesPerConnection)
    return Fail(detail, "advertised limits/endpoint wrong");
  return true;
}

bool NegotiateEqualMinor(std::string* detail) {
  return CheckHelloAck(RunNegotiate(1, 0, 1, 0, 9, 1), 0, 0, 9, 1, detail);
}

bool NegotiateNewerBroker(std::string* detail) {
  // broker_minor (7) > client_minor (3) -> selected == client_minor (3).
  return CheckHelloAck(RunNegotiate(1, 3, 1, 7, 9, 1), 3, 7, 9, 1, detail);
}

bool NegotiateNewerClient(std::string* detail) {
  // client_minor (7) > broker_minor (3) -> selected == broker_minor (3).
  return CheckHelloAck(RunNegotiate(1, 7, 1, 3, 9, 1), 3, 3, 9, 1, detail);
}

bool NegotiateMajorMismatch(std::string* detail) {
  NegotiationResult r = RunNegotiate(2, 0, 1, 0, 9, 1);
  if (r.decision != NegotiationDecision::kReject)
    return Fail(detail, "decision not kReject");
  FrameHeader out;
  const uint8_t* pl = nullptr;
  size_t pls = 0;
  if (DecodeAndValidateFrame(r.frame.data(), r.frame.size(), &out, &pl, &pls) !=
      DecodeStatus::kOk)
    return Fail(detail, "error frame decode failed");
  if (out.type != MessageType::ERROR)
    return Fail(detail, "reply not ERROR");
  if (out.request_id != 1)
    return Fail(detail, "request id not echoed");
  if (out.conn_id != 9)
    return Fail(detail, "assigned conn id not in reject header");
  if (out.version_major != 1)
    return Fail(detail, "broker major not spoken in reject");
  ErrorPayload p;
  if (!DecodeErrorPayload(pl, pls, &p))
    return Fail(detail, "error payload decode failed");
  if (p.status_code != StatusCode::ERROR_VERSION)
    return Fail(detail, "status not ERROR_VERSION");
  return true;
}

// ---------------------------------------------------------------------------
// cache suite: correlation + duplicate horizon (D18.9).
// ---------------------------------------------------------------------------
RequestIdentity MakeRequestId(uint32_t request_id, uint32_t session_id = 1) {
  RequestIdentity id;
  id.type = MessageType::CREATE_SESSION;
  id.conn_id = 1;
  id.session_id = session_id;
  id.run_id = 0;
  id.request_id = request_id;
  id.flags = 0;
  return id;
}

std::vector<uint8_t> PayloadSeed(uint32_t seed) {
  return {static_cast<uint8_t>(seed), static_cast<uint8_t>(seed >> 8),
          static_cast<uint8_t>(seed >> 16), static_cast<uint8_t>(seed >> 24)};
}

bool CacheFreshRecordReplay(std::string* detail) {
  RequestCache cache;
  const RequestIdentity id = MakeRequestId(1);
  const std::vector<uint8_t> payload = PayloadSeed(1);
  ClassifyResult first = cache.Classify(id, payload.data(), payload.size());
  if (first.classification != RequestClass::kFresh)
    return Fail(detail, "first classify not fresh");
  if (first.cached_response != nullptr)
    return Fail(detail, "fresh carried a response");
  const std::vector<uint8_t> response = {0xDE, 0xAD, 0xBE, 0xEF};
  cache.Record(id, payload.data(), payload.size(), response);
  if (cache.size() != 1 || cache.watermark() != 1)
    return Fail(detail, "record bookkeeping wrong");
  ClassifyResult replay = cache.Classify(id, payload.data(), payload.size());
  if (replay.classification != RequestClass::kExactDuplicate)
    return Fail(detail, "replay not exact duplicate");
  if (replay.cached_response == nullptr || *replay.cached_response != response)
    return Fail(detail, "cached response bytes mismatch");
  return true;
}

bool CacheMismatchedPayload(std::string* detail) {
  RequestCache cache;
  const RequestIdentity id = MakeRequestId(5);
  const std::vector<uint8_t> p1 = PayloadSeed(5);
  const std::vector<uint8_t> resp = {0x01};
  cache.Record(id, p1.data(), p1.size(), resp);
  const std::vector<uint8_t> p2 = PayloadSeed(6);  // same id, different payload
  ClassifyResult c = cache.Classify(id, p2.data(), p2.size());
  if (c.classification != RequestClass::kMismatchedDuplicate)
    return Fail(detail, "different payload not mismatched");
  if (c.cached_response != nullptr)
    return Fail(detail, "mismatch carried a response");
  return true;
}

bool CacheMismatchedIdentity(std::string* detail) {
  RequestCache cache;
  const RequestIdentity id = MakeRequestId(5, /*session_id=*/1);
  const std::vector<uint8_t> p = PayloadSeed(5);
  const std::vector<uint8_t> resp = {0x01};
  cache.Record(id, p.data(), p.size(), resp);
  const RequestIdentity id2 = MakeRequestId(5, /*session_id=*/2);
  ClassifyResult c = cache.Classify(id2, p.data(), p.size());
  if (c.classification != RequestClass::kMismatchedDuplicate)
    return Fail(detail, "different identity not mismatched");
  return true;
}

bool CacheFingerprintSensitive(std::string* detail) {
  RequestCache cache;
  const RequestIdentity id = MakeRequestId(1);
  const std::vector<uint8_t> base = {0x01, 0x02, 0x03};
  const std::vector<uint8_t> resp = {0xAA};
  cache.Record(id, base.data(), base.size(), resp);
  const std::vector<uint8_t> flipped = {0x01, 0x02, 0x04};  // one byte differs
  if (cache.Classify(id, flipped.data(), flipped.size()).classification !=
      RequestClass::kMismatchedDuplicate)
    return Fail(detail, "one-byte difference not detected");
  if (cache.Classify(id, base.data(), base.size()).classification !=
      RequestClass::kExactDuplicate)
    return Fail(detail, "identical payload not exact");
  return true;
}

bool CacheEvictionStale(std::string* detail) {
  RequestCache cache;
  const uint32_t total = kDuplicateCacheSize + 44;  // drive past the horizon
  for (uint32_t i = 1; i <= total; ++i) {
    const RequestIdentity id = MakeRequestId(i);
    const std::vector<uint8_t> payload = PayloadSeed(i);
    if (cache.Classify(id, payload.data(), payload.size()).classification !=
        RequestClass::kFresh)
      return Fail(detail, "monotonic request not fresh");
    cache.Record(id, payload.data(), payload.size(),
                 PayloadSeed(0xF00000 + i));
  }
  if (cache.size() != kDuplicateCacheSize)
    return Fail(detail, "cache exceeded the horizon");
  if (cache.watermark() != total)
    return Fail(detail, "watermark wrong");
  const uint32_t lowest = total - kDuplicateCacheSize + 1;  // oldest survivor
  // An evicted id is permanently stale, not re-executed.
  {
    const RequestIdentity id = MakeRequestId(1);
    const std::vector<uint8_t> payload = PayloadSeed(1);
    if (cache.Classify(id, payload.data(), payload.size()).classification !=
        RequestClass::kStale)
      return Fail(detail, "evicted id not stale");
  }
  // The boundary survivor still replays its recorded response exactly.
  {
    const RequestIdentity id = MakeRequestId(lowest);
    const std::vector<uint8_t> payload = PayloadSeed(lowest);
    ClassifyResult c = cache.Classify(id, payload.data(), payload.size());
    if (c.classification != RequestClass::kExactDuplicate)
      return Fail(detail, "surviving id not exact duplicate");
    const std::vector<uint8_t> expected = PayloadSeed(0xF00000 + lowest);
    if (c.cached_response == nullptr || *c.cached_response != expected)
      return Fail(detail, "survivor response wrong");
  }
  // A brand-new id above the watermark is fresh again.
  {
    const RequestIdentity id = MakeRequestId(total + 1);
    const std::vector<uint8_t> payload = PayloadSeed(total + 1);
    if (cache.Classify(id, payload.data(), payload.size()).classification !=
        RequestClass::kFresh)
      return Fail(detail, "above-watermark id not fresh");
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<TestCase> tests = {
      {"vectors", "canonical-all-distinct-header", CanonicalAllDistinctHeader},
      {"vectors", "canonical-hello-header", CanonicalHelloHeader},
      {"vectors", "canonical-writer-payload", CanonicalWriterPayload},
      {"vectors", "full-frame-round-trip", FullFrameRoundTrip},
      {"vectors", "canonical-hello-frame", CanonicalHelloFrame},
      {"vectors", "canonical-hello-ack-frame", CanonicalHelloAckFrame},
      {"vectors", "canonical-ack-frame", CanonicalAckFrame},
      {"vectors", "canonical-error-frame", CanonicalErrorFrame},
      {"protocol", "sha256-self-test", Sha256SelfTest},
      {"protocol", "header-round-trip", HeaderRoundTrip},
      {"protocol", "magic-reject", MagicReject},
      {"protocol", "truncation-every-prefix", TruncationEveryPrefix},
      {"protocol", "payload-length-bounds", PayloadLengthBounds},
      {"protocol", "exact-frame", ExactFrame},
      {"protocol", "reserved-flags", ReservedFlags},
      {"protocol", "reader-bounds", ReaderBounds},
      {"protocol", "writer-reader-round-trip", WriterReaderRoundTrip},
      {"protocol", "string-reader-valid", StringReaderValid},
      {"protocol", "string-reader-reject", StringReaderReject},
      {"messages", "hello-round-trip", MessagesHelloRoundTrip},
      {"messages", "hello-ack-round-trip", MessagesHelloAckRoundTrip},
      {"messages", "ack-round-trip", MessagesAckRoundTrip},
      {"messages", "error-round-trip", MessagesErrorRoundTrip},
      {"messages", "reject-bad-prologue", MessagesRejectBadPrologue},
      {"messages", "reject-framing", MessagesRejectFraming},
      {"messages", "reject-error-string", MessagesRejectErrorString},
      {"messages", "builders-stamp-type", MessagesBuildersStampType},
      {"messages", "correlation", MessagesCorrelation},
      {"negotiate", "equal-minor", NegotiateEqualMinor},
      {"negotiate", "newer-broker", NegotiateNewerBroker},
      {"negotiate", "newer-client", NegotiateNewerClient},
      {"negotiate", "major-mismatch", NegotiateMajorMismatch},
      {"cache", "fresh-record-replay", CacheFreshRecordReplay},
      {"cache", "mismatched-payload", CacheMismatchedPayload},
      {"cache", "mismatched-identity", CacheMismatchedIdentity},
      {"cache", "fingerprint-sensitive", CacheFingerprintSensitive},
      {"cache", "eviction-stale", CacheEvictionStale},
  };

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--vectors-only") == 0) {
      // One deterministic digest line over all canonical vectors (fixed order),
      // then run the vectors suite so a byte regression also fails here.
      std::printf("vectors-sha256=%s\n", Sha256Hex(CanonicalConcat()).c_str());
      std::fflush(stdout);
      char suite_arg[] = "--suite=vectors";
      char* synthetic[] = {argv[0], suite_arg};
      return v8host::test::RunTests(2, synthetic, tests);
    }
  }

  // `--all` (or no filter) runs everything; RunTests also honors --suite/--case.
  return v8host::test::RunTests(argc, argv, tests);
}
