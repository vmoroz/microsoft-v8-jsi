#include "v8host_payload_identity.h"

#include <bcrypt.h>

#include <cstring>
#include <vector>

namespace v8host {
namespace {

bool Sha256(const uint8_t* data,
            size_t size,
            std::array<uint8_t, 32>* digest) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD result_size = 0;
  std::vector<uint8_t> object;
  bool ok =
      BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(
          &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
      BCRYPT_SUCCESS(::BCryptGetProperty(
          algorithm, BCRYPT_OBJECT_LENGTH,
          reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
          &result_size, 0));
  if (ok) {
    object.resize(object_size);
    ok = BCRYPT_SUCCESS(::BCryptCreateHash(
             algorithm, &hash, object.data(), object_size, nullptr, 0, 0)) &&
         BCRYPT_SUCCESS(::BCryptHashData(
             hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0)) &&
         BCRYPT_SUCCESS(::BCryptFinishHash(
             hash, digest->data(), digest->size(), 0));
  }
  if (hash)
    ::BCryptDestroyHash(hash);
  if (algorithm)
    ::BCryptCloseAlgorithmProvider(algorithm, 0);
  return ok;
}

void AppendLe16(std::vector<uint8_t>* bytes, uint16_t value) {
  bytes->push_back(static_cast<uint8_t>(value));
  bytes->push_back(static_cast<uint8_t>(value >> 8));
}

}  // namespace

bool ComputePluginSetId(uint16_t machine,
                        const std::array<uint8_t, 32>& container_hash,
                        const std::array<uint8_t, 32>& plugin_hash,
                        std::array<uint8_t, 32>* out) {
  static constexpr char kDomain[] = "V8HOST-PLUGIN-SET-V1";
  if (!out)
    return false;
  std::vector<uint8_t> bytes(kDomain, kDomain + sizeof(kDomain));
  AppendLe16(&bytes, machine);
  AppendLe16(&bytes, kV8HostWireMajor);
  bytes.insert(bytes.end(), container_hash.begin(), container_hash.end());
  bytes.insert(bytes.end(), plugin_hash.begin(), plugin_hash.end());
  return Sha256(bytes.data(), bytes.size(), out);
}

bool DeriveInstallRoot(const std::wstring& container_final_path,
                       uint16_t machine,
                       std::wstring* out) {
  if (!out)
    return false;
  const std::wstring arch_dir = ParentPath(container_final_path);
  if (arch_dir.empty())
    return false;
  const size_t separator = arch_dir.find_last_of(L"\\/");
  const std::wstring arch_name = separator == std::wstring::npos
                                     ? arch_dir
                                     : arch_dir.substr(separator + 1);
  const wchar_t* expected = machine == IMAGE_FILE_MACHINE_AMD64   ? L"x64"
                            : machine == IMAGE_FILE_MACHINE_ARM64 ? L"arm64"
                                                                  : nullptr;
  if (expected &&
      ::CompareStringOrdinal(arch_name.c_str(), -1, expected, -1, TRUE) ==
          CSTR_EQUAL) {
    const std::wstring root = ParentPath(arch_dir);
    if (root.empty())
      return false;
    *out = root;
    return true;
  }
#if defined(SBOX_DEV_ALLOW_UNSIGNED)
  *out = arch_dir;
  return true;
#else
  return false;
#endif
}

bool ResolvePayloadIdentity(const std::wstring& directory,
                            const std::wstring& container_name,
                            const std::wstring& plugin_name,
                            PayloadIdentity* out,
                            DWORD* error) {
  if (!out || directory.empty()) {
    if (error)
      *error = ERROR_INVALID_PARAMETER;
    return false;
  }
  PayloadIdentity result;
  const std::wstring separator =
      (!directory.empty() && directory.back() == L'\\') ? L"" : L"\\";
  if (!OpenImmutableFile(directory + separator + container_name,
                         &result.container, error) ||
      !OpenImmutableFile(directory + separator + plugin_name, &result.plugin,
                         error) ||
      result.container.machine() != result.plugin.machine() ||
      !TrustAllowed(VerifyTrust(result.container)) ||
      !TrustAllowed(VerifyTrust(result.plugin)) ||
      !ComputePluginSetId(result.container.machine(),
                          result.container.sha256(), result.plugin.sha256(),
                          &result.plugin_set_id)) {
    if (error && *error == ERROR_SUCCESS)
      *error = ERROR_INVALID_IMAGE_HASH;
    return false;
  }
  result.native_machine = result.container.machine();
  if (!DeriveInstallRoot(result.container.final_path(), result.native_machine,
                         &result.install_root)) {
    if (error)
      *error = ERROR_BAD_PATHNAME;
    return false;
  }
  *out = std::move(result);
  if (error)
    *error = ERROR_SUCCESS;
  return true;
}

bool DeriveEndpoint(const std::vector<uint8_t>& sid,
                    const std::array<uint8_t, 32>& plugin_set_id,
                    BrokerMode mode,
                    const std::array<uint8_t, 16>* nonce,
                    std::wstring* endpoint,
                    std::array<uint8_t, 32>* key) {
  static constexpr char kDomain[] = "V8HOST-RENDEZVOUS-V1";
  if (!endpoint || !key || sid.empty() ||
      sid.size() > UINT16_MAX ||
      (mode == BrokerMode::kDedicated && !nonce))
    return false;
  std::vector<uint8_t> bytes(kDomain, kDomain + sizeof(kDomain));
  AppendLe16(&bytes, static_cast<uint16_t>(sid.size()));
  bytes.insert(bytes.end(), sid.begin(), sid.end());
  bytes.insert(bytes.end(), plugin_set_id.begin(), plugin_set_id.end());
  bytes.push_back(static_cast<uint8_t>(mode));
  if (mode == BrokerMode::kDedicated)
    bytes.insert(bytes.end(), nonce->begin(), nonce->end());
  if (!Sha256(bytes.data(), bytes.size(), key))
    return false;
  static constexpr wchar_t kHex[] = L"0123456789abcdef";
  *endpoint = L"\\\\.\\pipe\\v8host-rv1-";
  endpoint->reserve(endpoint->size() + key->size() * 2);
  for (uint8_t byte : *key) {
    endpoint->push_back(kHex[byte >> 4]);
    endpoint->push_back(kHex[byte & 0xf]);
  }
  return true;
}

bool GenerateNonce(std::array<uint8_t, 16>* nonce) {
  return nonce &&
         BCRYPT_SUCCESS(::BCryptGenRandom(
             nullptr, nonce->data(), nonce->size(),
             BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

std::string HexPrefix(const std::array<uint8_t, 32>& value, size_t bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  bytes = (std::min)(bytes, value.size());
  std::string result;
  result.reserve(bytes * 2);
  for (size_t i = 0; i < bytes; ++i) {
    result.push_back(kHex[value[i] >> 4]);
    result.push_back(kHex[value[i] & 0xf]);
  }
  return result;
}

}  // namespace v8host
