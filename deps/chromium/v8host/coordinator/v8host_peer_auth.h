#ifndef V8HOST_COORDINATOR_V8HOST_PEER_AUTH_H_
#define V8HOST_COORDINATOR_V8HOST_PEER_AUTH_H_

#include "v8host_file_identity.h"
#include "v8host_payload_identity.h"

#include <functional>

namespace v8host {

enum class PeerSide { kPipeClient, kPipeServer };

struct PeerAuthPolicy {
  PeerSide peer_side;
  BrokerMode mode;
  std::vector<uint8_t> expected_sid;
  LUID expected_session = {};
  std::wstring install_root;
  const HeldFile* expected_image = nullptr;
  HANDLE launched_process = nullptr;
};

// Test-only injection seam. Production callers pass nullptr (the default) and
// run entirely on the real OS-backed operations; a test may script where the
// peer PID, the resolved identity, or the creation-instance check come from in
// order to exercise fail-closed paths (PID reread mismatch, per-step query
// failure) that cannot be reproduced against a real local pipe. This never
// relaxes a check — it only substitutes the source of identity facts, and the
// same decision logic runs regardless.
struct PeerAuthHooks {
  std::function<bool(HANDLE, PeerSide, DWORD*)> read_peer_pid;
  std::function<bool(DWORD, HeldProcess*, DWORD*)> query_identity;
  std::function<bool(HANDLE, const HeldProcess&)> same_creation_instance;
};

bool AuthenticatePipePeer(HANDLE pipe,
                          const PeerAuthPolicy& policy,
                          HeldProcess* peer,
                          DWORD* error,
                          const PeerAuthHooks* hooks = nullptr);

}  // namespace v8host

#endif  // V8HOST_COORDINATOR_V8HOST_PEER_AUTH_H_
