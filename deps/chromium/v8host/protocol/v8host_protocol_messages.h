// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Contract B wire protocol — message layer: the HELLO / HELLO_ACK / ACK / ERROR
// payload codecs, version negotiation, request correlation, and the bounded
// duplicate-request cache. This builds on the framing core in
// v8host_protocol.h and reuses its Writer/Reader for all encoding/decoding.
// This wire surface is EXPERIMENTAL and NOT yet ABI-stable; it may be reshaped
// between revisions and must not be relied on as a stable contract yet.
//
// Like the framing core, every field crosses the wire as explicit little-endian
// fixed-width bytes (via Writer/Reader). No Windows types, pointers, handles,
// size_t, or wchar_t ever cross the wire, and no raw bytes are cast onto a
// native struct. The structs below are the DECODED form only.

#ifndef V8HOST_PROTOCOL_V8HOST_PROTOCOL_MESSAGES_H_
#define V8HOST_PROTOCOL_V8HOST_PROTOCOL_MESSAGES_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "v8host_protocol.h"

namespace v8host::protocol {

// Every version-1 control payload opens with this schema version and a reserved
// u16 that carries future capability bits; both are validated on decode.
inline constexpr uint16_t kMessageSchemaVersion = 1;

// HELLO_ACK endpoint_mode values (design §8.2). Numbered to match the shipped
// BrokerMode enum (common/v8host_payload_identity.h) and the Contract C
// V8HOST_BROKER_* macros — Dedicated=0, Shared=1 — so the wire value, the
// in-proc enum, and the client API share one numbering and never need an
// inversion. (The canonical HELLO_ACK test vector pins Shared=1 on the wire.)
inline constexpr uint32_t kEndpointModeDedicated = 0;
inline constexpr uint32_t kEndpointModeShared = 1;

// ---------------------------------------------------------------------------
// Payload structs (decoded form). Fixed defaults match a valid version-1
// payload; decode overwrites every field and validates schema_version/reserved.
// ---------------------------------------------------------------------------

// HELLO (client -> broker). Carries only the schema header in v1; the offered
// wire major/minor and the nonzero request_id live in the frame header.
struct HelloPayload {
  uint16_t schema_version = kMessageSchemaVersion;
  uint16_t reserved = 0;
};

// HELLO_ACK (broker -> client). Reports the broker's maximum version, the
// endpoint mode, and every frozen limit. The negotiated (selected) version
// rides in the frame header; broker_version_* here is the broker's maximum.
struct HelloAckPayload {
  uint16_t schema_version = kMessageSchemaVersion;
  uint16_t reserved = 0;
  uint16_t broker_version_major = 0;
  uint16_t broker_version_minor = 0;
  uint32_t endpoint_mode = kEndpointModeShared;
  uint32_t max_frame_payload = 0;
  uint32_t max_sessions_per_connection = 0;
  uint32_t max_in_flight_runs_per_session = 0;
  uint32_t max_file_rules = 0;
  uint32_t max_capabilities = 0;
  uint32_t max_queued_relay_bytes_per_run = 0;
  uint32_t max_queued_relay_bytes_per_connection = 0;
};

// ACK (broker -> client). A control request succeeded; the relevant
// correlation ids are echoed in the frame header.
struct AckPayload {
  uint16_t schema_version = kMessageSchemaVersion;
  uint16_t reserved = 0;
};

// ERROR (broker -> client). The frame header echoes the failing request's
// ids/flags; the message is a bounded, redacted diagnostic (no SIDs/paths) and
// may be empty. status_code is not range-validated on decode (forward-compat),
// matching how the framing core tolerates unknown message types.
struct ErrorPayload {
  uint16_t schema_version = kMessageSchemaVersion;
  uint16_t reserved = 0;
  StatusCode status_code = StatusCode::OK;
  std::string message;
};

// ---------------------------------------------------------------------------
// Payload codecs. Encode* append the payload body to `writer`; Decode* read the
// whole [data, data+size) payload, validate schema_version==1 and reserved==0,
// enforce strict UTF-8/no-NUL on strings, require the payload to be consumed
// exactly (no trailing or short bytes), and return false without writing *out
// on any failure.
// ---------------------------------------------------------------------------
void EncodeHelloPayload(const HelloPayload& payload, Writer& writer);
bool DecodeHelloPayload(const uint8_t* data, size_t size, HelloPayload* out);

void EncodeHelloAckPayload(const HelloAckPayload& payload, Writer& writer);
bool DecodeHelloAckPayload(const uint8_t* data, size_t size, HelloAckPayload* out);

void EncodeAckPayload(const AckPayload& payload, Writer& writer);
bool DecodeAckPayload(const uint8_t* data, size_t size, AckPayload* out);

void EncodeErrorPayload(const ErrorPayload& payload, Writer& writer);
bool DecodeErrorPayload(const uint8_t* data, size_t size, ErrorPayload* out);

// ---------------------------------------------------------------------------
// Full-frame builders. Each stamps header.type and header.payload_length, then
// emits header + payload as a ready-to-send buffer. The caller supplies the
// wire version, addressing (conn/session/run), request_id, and flags via
// `header`; the builder owns the type and length. (A caller-set header.type is
// overwritten.)
// ---------------------------------------------------------------------------
std::vector<uint8_t> BuildHelloFrame(FrameHeader header);
std::vector<uint8_t> BuildHelloAckFrame(FrameHeader header,
                                        const HelloAckPayload& payload);
std::vector<uint8_t> BuildAckFrame(FrameHeader header);
std::vector<uint8_t> BuildErrorFrame(FrameHeader header,
                                     const ErrorPayload& payload);

// ---------------------------------------------------------------------------
// Version negotiation (design §8.2). Pure decision + frame builder: no pipe or
// conn_id allocation happens here — the coordinator owns that and passes an
// already-assigned nonzero conn_id.
// ---------------------------------------------------------------------------

// The broker's own maximum version plus the capabilities it advertises in
// HELLO_ACK. Defaults to the wire version and the frozen limits.
struct BrokerCapabilities {
  uint16_t broker_version_major = kWireVersionMajor;
  uint16_t broker_version_minor = kWireVersionMinor;
  uint32_t endpoint_mode = kEndpointModeShared;
  uint32_t max_frame_payload = kMaxFramePayload;
  uint32_t max_sessions_per_connection = kMaxSessionsPerConnection;
  uint32_t max_in_flight_runs_per_session = kMaxInFlightRunsPerSession;
  uint32_t max_file_rules = kMaxFileRules;
  uint32_t max_capabilities = kMaxCapabilities;
  uint32_t max_queued_relay_bytes_per_run = kMaxQueuedRelayBytesPerRun;
  uint32_t max_queued_relay_bytes_per_connection =
      kMaxQueuedRelayBytesPerConnection;
};

enum class NegotiationDecision : uint32_t {
  kAck = 0,     // equal major: HELLO_ACK produced, connection proceeds
  kReject = 1,  // major mismatch: ERROR(ERROR_VERSION) produced, caller closes
};

struct NegotiationResult {
  NegotiationDecision decision = NegotiationDecision::kReject;
  // Valid only when decision == kAck: min(client_minor, broker_minor). Always
  // <= the client's offered minor, so the client can always operate at it.
  uint16_t selected_minor = 0;
  // The ready-to-send reply: HELLO_ACK (kAck) or ERROR (kReject).
  std::vector<uint8_t> frame;
};

// Decides the HELLO response. `hello_header` is the decoded client HELLO header
// (its version_major/minor are the client's offer and request_id is echoed);
// `hello` is the decoded HELLO payload (reserved for future capability bits).
// `assigned_conn_id` is the nonzero id the coordinator already assigned to this
// connection. On a major mismatch the result is kReject with an ERROR frame; on
// an equal major it is kAck with a HELLO_ACK frame whose header version is
// broker_major.selected_minor.
NegotiationResult NegotiateHello(const FrameHeader& hello_header,
                                 const HelloPayload& hello,
                                 const BrokerCapabilities& caps,
                                 uint32_t assigned_conn_id);

// ---------------------------------------------------------------------------
// Correlation + duplicate-request cache (design §8.3).
//
// Model (documented assumption): a connection's client control request_ids are
// NONZERO and MONOTONICALLY INCREASING. The cache keeps the 256 most recently
// completed control requests keyed by request_id, each storing the full request
// identity, a SHA-256 fingerprint of the request payload, and the response
// frame to replay. A watermark tracks the highest request_id ever recorded.
// ---------------------------------------------------------------------------

// The fields that must all match for a cached request to be an exact duplicate.
struct RequestIdentity {
  MessageType type = MessageType::HELLO;
  uint32_t conn_id = 0;
  uint32_t session_id = 0;
  uint32_t run_id = 0;
  uint32_t request_id = 0;
  uint16_t flags = 0;
};

bool operator==(const RequestIdentity& a, const RequestIdentity& b);
inline bool operator!=(const RequestIdentity& a, const RequestIdentity& b) {
  return !(a == b);
}

enum class RequestClass : uint32_t {
  kFresh = 0,  // request_id above the watermark, uncached: execute then Record
  kExactDuplicate = 1,  // cached, identity + fingerprint match: replay response
  kMismatchedDuplicate = 2,  // request_id cached but identity/payload differs:
                             // malformed, caller closes the connection
  kStale = 3,  // request_id <= watermark and uncached (evicted/reused-old):
               // caller returns ERROR_STALE_REQUEST, does NOT execute
};

struct ClassifyResult {
  RequestClass classification = RequestClass::kFresh;
  // Non-null only for kExactDuplicate: the cached response frame to replay.
  // Valid until the next Record() on the same cache.
  const std::vector<uint8_t>* cached_response = nullptr;
};

class RequestCache {
 public:
  // Classifies an incoming control request without mutating the cache. For
  // kExactDuplicate, the result carries a pointer to the cached response bytes.
  ClassifyResult Classify(const RequestIdentity& identity,
                          const uint8_t* payload,
                          size_t payload_len) const;

  // Records a completed request: stores the identity, the SHA-256 payload
  // fingerprint, and the response frame; evicts the lowest (oldest) request_id
  // when the size would exceed kDuplicateCacheSize; raises the watermark to
  // max(watermark, request_id). Call only after a kFresh classification.
  void Record(const RequestIdentity& identity,
              const uint8_t* payload,
              size_t payload_len,
              std::vector<uint8_t> response_frame);

  size_t size() const { return entries_.size(); }
  uint32_t watermark() const { return watermark_; }

 private:
  struct Entry {
    RequestIdentity identity;
    uint8_t fingerprint[32] = {};
    std::vector<uint8_t> response;
  };

  // Keyed by request_id and ordered ascending, so begin() is both the lowest
  // request_id and (given monotonic ids) the oldest entry to evict.
  std::map<uint32_t, Entry> entries_;
  uint32_t watermark_ = 0;
};

}  // namespace v8host::protocol

#endif  // V8HOST_PROTOCOL_V8HOST_PROTOCOL_MESSAGES_H_
