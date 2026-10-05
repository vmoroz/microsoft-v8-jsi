#include "v8host_broker_rendezvous.h"

#include "v8host_peer_auth.h"

#include <algorithm>
#include <utility>

namespace v8host {
namespace {

constexpr uint32_t kProbeMagic = 0x31504256;
constexpr uint32_t kProbeResponseMagic = 0x31524256;

void PutLe32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

uint32_t GetLe32(const uint8_t* in) {
  return static_cast<uint32_t>(in[0]) |
         (static_cast<uint32_t>(in[1]) << 8) |
         (static_cast<uint32_t>(in[2]) << 16) |
         (static_cast<uint32_t>(in[3]) << 24);
}

bool IoWithDeadline(HANDLE pipe,
                    bool write,
                    void* buffer,
                    DWORD size,
                    DWORD timeout_ms) {
  OVERLAPPED overlapped = {};
  overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!overlapped.hEvent)
    return false;
  DWORD transferred = 0;
  BOOL started =
      write ? ::WriteFile(pipe, buffer, size, nullptr, &overlapped)
            : ::ReadFile(pipe, buffer, size, nullptr, &overlapped);
  bool pending = !started && ::GetLastError() == ERROR_IO_PENDING;
  bool ok = false;
  if (started) {
    ok = ::GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) != FALSE;
  } else if (pending &&
             ::WaitForSingleObject(overlapped.hEvent, timeout_ms) ==
                 WAIT_OBJECT_0) {
    ok = ::GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) != FALSE;
    pending = false;
  }
  if (pending) {
    ::CancelIoEx(pipe, &overlapped);
    ::GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
  }
  ::CloseHandle(overlapped.hEvent);
  return ok && transferred == size;
}

std::wstring Quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

std::wstring NonceHex(const std::array<uint8_t, 16>& nonce) {
  static constexpr wchar_t kHex[] = L"0123456789abcdef";
  std::wstring result;
  result.reserve(32);
  for (uint8_t byte : nonce) {
    result.push_back(kHex[byte >> 4]);
    result.push_back(kHex[byte & 0xf]);
  }
  return result;
}

}  // namespace

struct BrokerConnection::State {
  HANDLE pipe = INVALID_HANDLE_VALUE;
  HeldProcess server;
  HeldFile plugin;
  std::wstring endpoint;
  BrokerMode mode = BrokerMode::kShared;
};

BrokerConnection::BrokerConnection() : state_(std::make_unique<State>()) {}
BrokerConnection::~BrokerConnection() {
  Close();
}
BrokerConnection::BrokerConnection(BrokerConnection&&) noexcept = default;
BrokerConnection& BrokerConnection::operator=(BrokerConnection&&) noexcept =
    default;

HANDLE BrokerConnection::pipe() const {
  return state_ ? state_->pipe : INVALID_HANDLE_VALUE;
}

DWORD BrokerConnection::broker_pid() const {
  return state_ && state_->server ? state_->server.pid() : 0;
}

const std::wstring& BrokerConnection::endpoint() const {
  static const std::wstring empty;
  return state_ ? state_->endpoint : empty;
}

void BrokerConnection::Close() {
  if (state_ && state_->pipe != INVALID_HANDLE_VALUE) {
    ::CancelIoEx(state_->pipe, nullptr);
    ::CloseHandle(state_->pipe);
    state_->pipe = INVALID_HANDLE_VALUE;
  }
}

RendezvousStatus BrokerConnection::Probe(uint32_t sequence,
                                         ProbeResult* result) {
  if (!result || pipe() == INVALID_HANDLE_VALUE)
    return RendezvousStatus::kInvalidArgument;
  uint8_t request[16] = {};
  PutLe32(request, kProbeMagic);
  PutLe32(request + 4, static_cast<uint32_t>(state_->mode));
  PutLe32(request + 8, sequence);
  uint8_t response[24] = {};
  const bool wrote =
      IoWithDeadline(pipe(), true, request, sizeof(request), 2000);
  const bool read =
      wrote && IoWithDeadline(pipe(), false, response, sizeof(response), 2000);
  if (!wrote || !read ||
      GetLe32(response) != kProbeResponseMagic ||
      GetLe32(response + 12) != sequence) {
    return RendezvousStatus::kIoFailed;
  }
  result->broker_pid = GetLe32(response + 4);
  result->observed_client_pid = GetLe32(response + 8);
  result->sequence = GetLe32(response + 12);
  return RendezvousStatus::kOk;
}

BrokerRendezvous::BrokerRendezvous(std::wstring payload_directory,
                                   BrokerMode mode)
    : payload_directory_(std::move(payload_directory)), mode_(mode) {}

RendezvousStatus BrokerRendezvous::Initialize() {
  DWORD error = ERROR_SUCCESS;
  if (!ResolvePayloadIdentity(payload_directory_, L"sbox.exe", L"v8host.dll",
                              &payload_, &error))
    return RendezvousStatus::kPayloadInvalid;
  if (!QueryCurrentSidAndSession(&sid_, &session_, &error))
    return RendezvousStatus::kPeerAuthenticationFailed;
  const std::array<uint8_t, 16>* nonce = nullptr;
  if (mode_ == BrokerMode::kDedicated) {
    if (!GenerateNonce(&nonce_))
      return RendezvousStatus::kEndpointInvalid;
    nonce = &nonce_;
  }
  if (!DeriveEndpoint(sid_, payload_.plugin_set_id, mode_, nonce, &endpoint_,
                      &endpoint_key_))
    return RendezvousStatus::kEndpointInvalid;
  initialized_ = true;
  return RendezvousStatus::kOk;
}

RendezvousStatus BrokerRendezvous::TryConnect(
    HANDLE launched_process,
    BrokerConnection* connection) {
  HANDLE pipe =
      ::CreateFileW(endpoint_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                    OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  if (pipe == INVALID_HANDLE_VALUE)
    return RendezvousStatus::kStartTimeout;
  DWORD mode = PIPE_READMODE_MESSAGE;
  if (!::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
    ::CloseHandle(pipe);
    return RendezvousStatus::kIoFailed;
  }
  PeerAuthPolicy policy = {};
  policy.peer_side = PeerSide::kPipeServer;
  policy.mode = mode_;
  policy.expected_sid = sid_;
  policy.expected_session = session_;
  policy.install_root = payload_.install_root;
  policy.expected_image = &payload_.container;
  policy.launched_process = launched_process;
  HeldProcess server;
  DWORD error = ERROR_SUCCESS;
  if (!AuthenticatePipePeer(pipe, policy, &server, &error)) {
    ::CloseHandle(pipe);
    return RendezvousStatus::kPeerAuthenticationFailed;
  }
  HeldFile plugin;
  if (!OpenImmutableFile(payload_.plugin.final_path(), &plugin, &error) ||
      !IsSameFileIdentity(plugin, payload_.plugin) ||
      !TrustAllowed(VerifyTrust(plugin))) {
    ::CloseHandle(pipe);
    return RendezvousStatus::kPeerAuthenticationFailed;
  }
  connection->Close();
  connection->state_->pipe = pipe;
  connection->state_->server = std::move(server);
  connection->state_->plugin = std::move(plugin);
  connection->state_->endpoint = endpoint_;
  connection->state_->mode = mode_;
  return RendezvousStatus::kOk;
}

RendezvousStatus BrokerRendezvous::LaunchCandidate(
    PROCESS_INFORMATION* process) {
  const std::wstring executable =
      payload_directory_ +
      (payload_directory_.back() == L'\\' ? L"" : L"\\") + L"sbox.exe";
  std::wstring command =
      Quote(executable) + L" --broker --mode=" +
      (mode_ == BrokerMode::kShared ? L"shared" : L"dedicated") +
      L" --pipe=" + Quote(endpoint_) + L" --plugin v8host.dll";
  if (mode_ == BrokerMode::kDedicated)
    command += L" --nonce=" + NonceHex(nonce_);
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  *process = {};
  if (!::CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
                        FALSE, 0, nullptr,
                        payload_directory_.c_str(), &startup, process))
    return RendezvousStatus::kLaunchFailed;
  return RendezvousStatus::kOk;
}

RendezvousStatus BrokerRendezvous::ConnectOrLaunch(
    BrokerConnection* connection) {
  if (!connection)
    return RendezvousStatus::kInvalidArgument;
  if (!initialized_) {
    RendezvousStatus status = Initialize();
    if (status != RendezvousStatus::kOk)
      return status;
  }
  if (mode_ == BrokerMode::kShared) {
    RendezvousStatus existing = TryConnect(nullptr, connection);
    if (existing == RendezvousStatus::kOk)
      return existing;
    if (existing == RendezvousStatus::kPeerAuthenticationFailed)
      return existing;
  }
  PROCESS_INFORMATION candidate = {};
  RendezvousStatus status = LaunchCandidate(&candidate);
  if (status != RendezvousStatus::kOk)
    return status;
  ::CloseHandle(candidate.hThread);
  const ULONGLONG deadline = ::GetTickCount64() + 5000;
  DWORD delay = 10;
  while (::GetTickCount64() < deadline) {
    HANDLE binding = candidate.hProcess;
    DWORD exit_code = STILL_ACTIVE;
    if (::GetExitCodeProcess(candidate.hProcess, &exit_code) &&
        exit_code != STILL_ACTIVE) {
      if (mode_ == BrokerMode::kDedicated || exit_code != 0) {
        ::CloseHandle(candidate.hProcess);
        return RendezvousStatus::kLaunchFailed;
      }
      binding = nullptr;
    }
    status = TryConnect(binding, connection);
    if (status == RendezvousStatus::kOk) {
      ::CloseHandle(candidate.hProcess);
      return status;
    }
    if (status == RendezvousStatus::kPeerAuthenticationFailed) {
      if (mode_ == BrokerMode::kShared &&
          ::WaitForSingleObject(candidate.hProcess, 500) == WAIT_OBJECT_0) {
        DWORD loser_exit = 1;
        if (::GetExitCodeProcess(candidate.hProcess, &loser_exit) &&
            loser_exit == 0) {
          ::Sleep(delay);
          continue;
        }
      }
      ::CloseHandle(candidate.hProcess);
      return status;
    }
    ::Sleep(delay);
    delay = (std::min)(delay * 2, static_cast<DWORD>(250));
  }
  ::CloseHandle(candidate.hProcess);
  return RendezvousStatus::kStartTimeout;
}

}  // namespace v8host
