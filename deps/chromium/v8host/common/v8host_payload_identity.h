#ifndef V8HOST_COMMON_V8HOST_PAYLOAD_IDENTITY_H_
#define V8HOST_COMMON_V8HOST_PAYLOAD_IDENTITY_H_

#include "v8host_file_identity.h"

#include <array>
#include <string>
#include <vector>

namespace v8host {

constexpr uint16_t kV8HostWireMajor = 1;

enum class BrokerMode : uint8_t { kDedicated = 0, kShared = 1 };

struct PayloadIdentity {
  HeldFile container;
  HeldFile plugin;
  uint16_t native_machine = 0;
  std::array<uint8_t, 32> plugin_set_id = {};
  std::wstring install_root;
};

bool ResolvePayloadIdentity(const std::wstring& directory,
                            const std::wstring& container_name,
                            const std::wstring& plugin_name,
                            PayloadIdentity* out,
                            DWORD* error);
bool ComputePluginSetId(uint16_t machine,
                        const std::array<uint8_t, 32>& container_hash,
                        const std::array<uint8_t, 32>& plugin_hash,
                        std::array<uint8_t, 32>* out);
// Derives the install root used for the shared co-location check. Release
// layout is `<root>\<native-arch>\sbox.exe`, so the root is the parent of the
// architecture directory whose name must match the container's PE machine. A
// non-architecture parent is accepted as the root only in developer builds
// (SBOX_DEV_ALLOW_UNSIGNED); release builds fail closed. Never trust a
// client-supplied root.
bool DeriveInstallRoot(const std::wstring& container_final_path,
                       uint16_t machine,
                       std::wstring* out);
bool DeriveEndpoint(const std::vector<uint8_t>& sid,
                    const std::array<uint8_t, 32>& plugin_set_id,
                    BrokerMode mode,
                    const std::array<uint8_t, 16>* nonce,
                    std::wstring* endpoint,
                    std::array<uint8_t, 32>* key);
bool GenerateNonce(std::array<uint8_t, 16>* nonce);
std::string HexPrefix(const std::array<uint8_t, 32>& value, size_t bytes);

}  // namespace v8host

#endif  // V8HOST_COMMON_V8HOST_PAYLOAD_IDENTITY_H_
