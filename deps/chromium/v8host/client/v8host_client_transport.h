// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#ifndef V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_
#define V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_

#include "v8host_client.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace v8host::client {

enum class TransportDisconnect { kBrokerLost, kConnectFailed, kProtocolError };

class ClientTransportDelegate {
 public:
  virtual ~ClientTransportDelegate() = default;
  virtual void OnInboundFrame(const uint8_t* bytes, size_t len) = 0;
  virtual void OnDisconnect(TransportDisconnect reason) = 0;
};

class ClientTransport {
 public:
  virtual ~ClientTransport() = default;
  virtual V8HostStatus Start() = 0;
  virtual V8HostStatus SendFrame(const uint8_t* bytes, size_t len) = 0;
  virtual uint32_t conn_id() const = 0;
  virtual void Close() = 0;
};

struct TransportParams {
  std::wstring payload_directory;
  int32_t broker_mode = 0;
};

using ClientTransportFactory =
    ClientTransport* (*)(const TransportParams&, ClientTransportDelegate*);

ClientTransport* CreateRealPipeClientTransport(const TransportParams& params,
                                               ClientTransportDelegate* delegate);

#ifdef V8HOST_CLIENT_TESTING
void SetTransportFactoryForTesting(ClientTransportFactory factory);
void SetInitializeAfterDispatcherHookForTesting(void (*hook)());
uint32_t LifecycleThreadIdForTesting();
uint32_t LastSessionDeleteThreadIdForTesting();
void SetInboundStatusObserverForTesting(void (*observer)(V8HostStatus));
#endif

}  // namespace v8host::client

#endif  // V8HOST_CLIENT_V8HOST_CLIENT_TRANSPORT_H_
