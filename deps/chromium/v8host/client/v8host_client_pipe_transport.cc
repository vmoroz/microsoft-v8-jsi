// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_client_transport.h"

#include <new>
#include <utility>

namespace v8host::client {
namespace {

// Stage-4 fill-in boundary: Start will run BrokerRendezvous connect/launch and
// handshake on a background thread, then own the overlapped read loop.
// SendFrame will queue/write frames, and Close will cancel I/O and arrange the
// join off the caller's thread. Stage 3 deliberately performs no pipe I/O.
class PipeClientTransport final : public ClientTransport {
 public:
  PipeClientTransport(TransportParams params, ClientTransportDelegate* delegate)
      : params_(std::move(params)), delegate_(delegate) {}

  V8HostStatus Start() override {
    (void)params_;
    (void)delegate_;
    return V8HOST_E_CONNECT;
  }
  V8HostStatus SendFrame(const uint8_t*, size_t) override {
    return V8HOST_E_CONNECT;
  }
  uint32_t conn_id() const override { return 0; }
  void Close() override {}

 private:
  TransportParams params_;
  ClientTransportDelegate* delegate_;
};

}  // namespace

ClientTransport* CreateRealPipeClientTransport(
    const TransportParams& params,
    ClientTransportDelegate* delegate) {
  return new (std::nothrow) PipeClientTransport(params, delegate);
}

}  // namespace v8host::client
