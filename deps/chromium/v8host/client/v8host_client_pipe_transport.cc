// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "v8host_client_transport.h"

#include <new>
#include <utility>

namespace v8host::client {
namespace {

// Transport skeleton: fail closed without pipe I/O until background
// rendezvous, reads, writes, cancellation and joined teardown are implemented.
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
