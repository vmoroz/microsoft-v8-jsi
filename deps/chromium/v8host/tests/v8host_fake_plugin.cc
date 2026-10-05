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
