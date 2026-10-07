// The final-DLL composition seam. Persona implementations remain in separate
// source sets; only this translation unit assembles their plugin callbacks.

#include "sbox.h"
#include "v8host_broker.h"
#include "v8host_engine.h"

namespace {

sbox_status SBOX_CALL BrokerRun(sbox_broker broker,
                                const sbox_broker_api* api,
                                const sbox_broker_start* start) {
  return V8HostBrokerRun(broker, api, start);
}

const sbox_plugin kPlugin = {
    sizeof(sbox_plugin),       SBOX_ABI_VERSION,      &V8HostEngineConfigure,
    &BrokerRun,                &V8HostEngineWarmup,   &V8HostEngineRun,
    &V8HostEngineShutdown,
};

}  // namespace

extern "C" __declspec(dllexport) sbox_status SBOX_CALL sbox_plugin_main(
    uint32_t host_abi_version, const sbox_plugin** out) {
  if (!out)
    return sbox_error_args;
  if (host_abi_version != SBOX_ABI_VERSION)
    return sbox_error_version;
  *out = &kPlugin;
  return sbox_ok;
}
