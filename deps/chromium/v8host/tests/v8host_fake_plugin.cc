#if defined(V8HOST_ABI4_FIXTURE)
#include "sbox.h"
namespace {
sbox_status SBOX_CALL Configure(sbox_config, const sbox_config_api*, const void*, size_t) { return sbox_ok; }
sbox_status SBOX_CALL Broker(sbox_broker, const sbox_broker_api*, const sbox_broker_start*) { return sbox_ok; }
sbox_status SBOX_CALL Worker(sbox_worker, const sbox_worker_api*) { return sbox_ok; }
void SBOX_CALL Shutdown(sbox_worker) {}
const sbox_plugin kAbi4 = {sizeof(sbox_plugin), 4u, Configure, Broker, Worker, Worker, Shutdown};
}
extern "C" __declspec(dllexport) sbox_status SBOX_CALL sbox_plugin_main(
    uint32_t host_abi_version, const sbox_plugin** out) {
  if (!out) return sbox_error_args;
  if (host_abi_version != 4u) return sbox_error_version;
  *out = &kAbi4;
  return sbox_ok;
}
#else
// A deliberately invalid sbox plugin for negative ABI coverage: it resolves by
// name but reports the wrong ABI version and a vtable of null entries, so the
// generic host must reject it before driving any lifecycle. Test-only.
#include "sbox.h"

extern "C" __declspec(dllexport) sbox_status SBOX_CALL sbox_plugin_main(
    uint32_t /*host_abi_version*/,
    const sbox_plugin** out) {
  static const sbox_plugin kInvalid = {sizeof(sbox_plugin),
                                       1u,  // not SBOX_ABI_VERSION
                                       nullptr,
                                       nullptr,
                                       nullptr,
                                       nullptr,
                                       nullptr};
  if (out)
    *out = &kInvalid;
  return sbox_ok;
}

#endif
