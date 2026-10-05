#ifndef V8HOST_CLIENT_V8HOST_BROKER_RENDEZVOUS_H_
#define V8HOST_CLIENT_V8HOST_BROKER_RENDEZVOUS_H_

#include "v8host_payload_identity.h"

#include <memory>

namespace v8host {

enum class RendezvousStatus {
  kOk,
  kInvalidArgument,
  kPayloadInvalid,
  kEndpointInvalid,
  kLaunchFailed,
  kStartTimeout,
  kPeerAuthenticationFailed,
  kIoFailed,
};

struct ProbeResult {
  DWORD broker_pid = 0;
  DWORD observed_client_pid = 0;
  uint32_t sequence = 0;
};

class BrokerConnection {
 public:
  BrokerConnection();
  ~BrokerConnection();
  BrokerConnection(BrokerConnection&&) noexcept;
  BrokerConnection& operator=(BrokerConnection&&) noexcept;
  BrokerConnection(const BrokerConnection&) = delete;
  BrokerConnection& operator=(const BrokerConnection&) = delete;

  HANDLE pipe() const;
  DWORD broker_pid() const;
  const std::wstring& endpoint() const;
  RendezvousStatus Probe(uint32_t sequence, ProbeResult* result);
  void Close();

 private:
  friend class BrokerRendezvous;
  struct State;
  std::unique_ptr<State> state_;
};

class BrokerRendezvous {
 public:
  BrokerRendezvous(std::wstring payload_directory, BrokerMode mode);
  RendezvousStatus ConnectOrLaunch(BrokerConnection* connection);

  const std::wstring& endpoint() const { return endpoint_; }
  const std::array<uint8_t, 32>& endpoint_key() const { return endpoint_key_; }

 private:
  RendezvousStatus Initialize();
  RendezvousStatus TryConnect(HANDLE launched_process,
                              BrokerConnection* connection);
  RendezvousStatus LaunchCandidate(PROCESS_INFORMATION* process);

  std::wstring payload_directory_;
  BrokerMode mode_;
  PayloadIdentity payload_;
  std::vector<uint8_t> sid_;
  LUID session_ = {};
  std::array<uint8_t, 16> nonce_ = {};
  std::array<uint8_t, 32> endpoint_key_ = {};
  std::wstring endpoint_;
  bool initialized_ = false;
};

}  // namespace v8host

#endif  // V8HOST_CLIENT_V8HOST_BROKER_RENDEZVOUS_H_
