// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#ifndef V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_
#define V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_

#include "v8host_client.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <memory>
#ifdef V8HOST_CLIENT_TESTING
#include "v8host_broker_rendezvous.h"
#endif

namespace v8host::client {

enum class TransportDisconnect { kBrokerLost, kConnectFailed, kProtocolError };

// Production callbacks run on the I/O pump, without queue locks held.
// OnConnected publishes the assigned connection/negotiated versions before frames.
// Callbacks may race with or arrive after Close; delegates must tolerate them.
class ClientTransportDelegate {
 public:
  virtual ~ClientTransportDelegate() = default;
  virtual void OnConnected(uint32_t conn_id, uint16_t major, uint16_t minor) = 0;
  virtual void OnInboundFrame(const uint8_t* bytes, size_t len) = 0;
  virtual void OnDisconnect(TransportDisconnect reason) = 0;
};

class ClientTransport {
 public:
  virtual ~ClientTransport() = default;
  // Start(delegate) retains the delegate through background cleanup; production
  // Start() without a lease fails. The caller publishes a returned startup error;
  // asynchronous failure is reported via OnDisconnect.
  // SendFrame copies and enqueues: OK is not delivery; QUOTA admits nothing,
  // CONNECT means closed/terminal, and PROTOCOL means an invalid frame.
  // Close is idempotent, nonblocking and callable from a callback.
  virtual V8HostStatus Start() = 0;
  virtual V8HostStatus Start(std::shared_ptr<ClientTransportDelegate> delegate) {
    return Start();
  }
  virtual V8HostStatus SendFrame(const uint8_t* bytes, size_t len) = 0;
  virtual uint32_t conn_id() const = 0;
  virtual void Close() = 0;
#ifdef V8HOST_CLIENT_TESTING
  virtual size_t QueuedBytesForTesting() { return 0; }
#endif
};

struct TransportParams {
  std::wstring payload_directory;
  int32_t broker_mode = 0;
#ifdef V8HOST_CLIENT_TESTING
  void* test_context = nullptr;
  void (*test_pending)(void*, bool) = nullptr;
  RendezvousStatus (*test_connect)(void*, BrokerConnection*, HelloResult*, HANDLE,
                                   ULONGLONG) = nullptr;
#endif
};

using ClientTransportFactory =
    ClientTransport* (*)(const TransportParams&, ClientTransportDelegate*);

ClientTransport* CreateRealPipeClientTransport(const TransportParams& params,
                                               ClientTransportDelegate* delegate);

#ifdef V8HOST_CLIENT_TESTING
void SetSubmissionHooksForTesting(void (*before)(), void (*admitted)());
V8HostStatus SubmitCancelForTesting(V8HostSession* session, uint32_t run);
void SetIdsForTesting(V8HostSession* session, uint32_t request, uint32_t run);
void SetTransportFactoryForTesting(ClientTransportFactory factory);
void SetInitializeAfterDispatcherHookForTesting(void (*hook)());
uint32_t LifecycleThreadIdForTesting();
uint32_t LastSessionDeleteThreadIdForTesting();
void SetInboundStatusObserverForTesting(void (*observer)(V8HostStatus));
#endif

}  // namespace v8host::client

#endif  // V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_
