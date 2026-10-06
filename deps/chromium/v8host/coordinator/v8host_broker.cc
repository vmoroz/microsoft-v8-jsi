#include "v8host_broker.h"

#include "v8host_file_identity.h"
#include "v8host_payload_identity.h"
#include "v8host_peer_auth.h"
#include "v8host_protocol.h"
#include "v8host_protocol_messages.h"

#include <sddl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {

namespace protocol = v8host::protocol;

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

// Reads exactly one pipe message (a full Contract B frame) into a bounded
// buffer. The transferred size is variable, so success does not require filling
// the buffer. Handshake control frames are small (HELLO is 36 bytes); a message
// larger than the buffer surfaces as ERROR_MORE_DATA and is fatal
// (fail-closed), never reassembled.
bool ReadFrameMessage(HANDLE pipe,
                      uint8_t* buf,
                      DWORD buf_size,
                      DWORD* out_len,
                      DWORD timeout_ms) {
  OVERLAPPED overlapped = {};
  overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (!overlapped.hEvent)
    return false;
  DWORD transferred = 0;
  BOOL started = ::ReadFile(pipe, buf, buf_size, nullptr, &overlapped);
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
  if (ok)
    *out_len = transferred;
  return ok;
}

class PipeSecurity {
 public:
  ~PipeSecurity() {
    if (descriptor_)
      ::LocalFree(descriptor_);
  }
  bool Initialize(const std::vector<uint8_t>& sid) {
    LPWSTR sid_string = nullptr;
    if (!::ConvertSidToStringSidW(
            const_cast<uint8_t*>(sid.data()), &sid_string))
      return false;
    std::wstring sddl = L"D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;";
    sddl += sid_string;
    sddl += L")";
    ::LocalFree(sid_string);
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor_, nullptr))
      return false;
    attributes_.nLength = sizeof(attributes_);
    attributes_.lpSecurityDescriptor = descriptor_;
    return true;
  }
  SECURITY_ATTRIBUTES* get() { return &attributes_; }

 private:
  PSECURITY_DESCRIPTOR descriptor_ = nullptr;
  SECURITY_ATTRIBUTES attributes_ = {};
};

class BrokerService {
 public:
  BrokerService(const sbox_broker_start* start,
                v8host::PayloadIdentity payload,
                std::vector<uint8_t> sid,
                LUID session)
      : start_(start),
        payload_(std::move(payload)),
        sid_(std::move(sid)),
        session_(session),
        mode_(start->mode == sbox_broker_mode_shared
                  ? v8host::BrokerMode::kShared
                  : v8host::BrokerMode::kDedicated) {}

  sbox_status Run() {
    if (!security_.Initialize(sid_))
      return sbox_error;
    bool first = true;
    auto zero_since = std::chrono::steady_clock::now();
    bool zero_timing = false;
    while (!draining_) {
      if (mode_ == v8host::BrokerMode::kDedicated && owner_seen_)
        break;
      HANDLE pipe = ::CreateNamedPipeW(
          start_->endpoint_name,
          PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
              (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
          PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
              PIPE_REJECT_REMOTE_CLIENTS,
          mode_ == v8host::BrokerMode::kShared ? PIPE_UNLIMITED_INSTANCES : 1,
          4096, 4096, 0, security_.get());
      if (pipe == INVALID_HANDLE_VALUE) {
        const DWORD pipe_error = ::GetLastError();
        if (first && pipe_error == ERROR_ACCESS_DENIED &&
            mode_ == v8host::BrokerMode::kShared) {
          const bool winner_ok = AuthenticateWinningBroker();
          if (!winner_ok)
            printf("[v8host] shared race: winner authentication failed\n");
          return winner_ok ? sbox_ok : sbox_error;
        }
        printf("[v8host] pipe creation failed category=%lu first=%d\n",
               pipe_error, first ? 1 : 0);
        return sbox_error;
      }
      first = false;
      OVERLAPPED overlapped = {};
      overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
      bool connected = false;
      bool pending = false;
      if (::ConnectNamedPipe(pipe, &overlapped)) {
        connected = true;
      } else if (::GetLastError() == ERROR_PIPE_CONNECTED) {
        connected = true;
      } else if (::GetLastError() == ERROR_IO_PENDING) {
        pending = true;
        if (::WaitForSingleObject(overlapped.hEvent, 100) == WAIT_OBJECT_0) {
          DWORD transferred = 0;
          connected =
              ::GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) !=
              FALSE;
          pending = false;
        }
      }
      if (pending) {
        ::CancelIoEx(pipe, &overlapped);
        DWORD aborted = 0;
        ::GetOverlappedResult(pipe, &overlapped, &aborted, TRUE);
      }
      ::CloseHandle(overlapped.hEvent);
      if (connected) {
        {
          std::lock_guard<std::mutex> lock(mutex_);
          ++setup_count_;
          zero_timing = false;
        }
        auto context = std::make_unique<ConnectionContext>();
        context->service = this;
        context->pipe = pipe;
        HANDLE task = ::CreateThread(nullptr, 0, &ConnectionTask,
                                     context.get(), 0, nullptr);
        if (task) {
          context.release();
          tasks_.push_back(task);
        } else {
          {
            std::lock_guard<std::mutex> lock(mutex_);
            --setup_count_;
          }
          ::CloseHandle(pipe);
        }
        if (mode_ == v8host::BrokerMode::kDedicated)
          break;
      } else {
        ::CloseHandle(pipe);
      }
      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (setup_count_ == 0 && connection_count_ == 0) {
          if (!zero_timing) {
            zero_since = std::chrono::steady_clock::now();
            zero_timing = true;
          } else if (mode_ == v8host::BrokerMode::kShared &&
                     std::chrono::steady_clock::now() - zero_since >=
                         std::chrono::seconds(5)) {
            draining_ = true;
          }
        } else {
          zero_timing = false;
        }
      }
    }
    for (HANDLE task : tasks_) {
      ::WaitForSingleObject(task, INFINITE);
      ::CloseHandle(task);
    }
    return sbox_ok;
  }

 private:
  struct ConnectionContext {
    BrokerService* service = nullptr;
    HANDLE pipe = INVALID_HANDLE_VALUE;
  };

  static DWORD WINAPI ConnectionTask(void* raw_context) {
    std::unique_ptr<ConnectionContext> context(
        static_cast<ConnectionContext*>(raw_context));
    context->service->ServeConnection(context->pipe);
    return 0;
  }

  bool AuthenticateWinningBroker() {
    const ULONGLONG deadline = ::GetTickCount64() + 5000;
    DWORD delay = 10;
    while (::GetTickCount64() < deadline) {
      HANDLE pipe =
          ::CreateFileW(start_->endpoint_name, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
      if (pipe != INVALID_HANDLE_VALUE) {
        v8host::PeerAuthPolicy policy = {};
        policy.peer_side = v8host::PeerSide::kPipeServer;
        policy.mode = mode_;
        policy.expected_sid = sid_;
        policy.expected_session = session_;
        policy.install_root = payload_.install_root;
        policy.expected_image = &payload_.container;
        v8host::HeldProcess peer;
        DWORD error = ERROR_SUCCESS;
        const bool ok =
            v8host::AuthenticatePipePeer(pipe, policy, &peer, &error);
        ::CloseHandle(pipe);
        return ok;
      }
      if (::GetLastError() == ERROR_PIPE_BUSY)
        ::WaitNamedPipeW(start_->endpoint_name, delay);
      else
        ::Sleep(delay);
      delay = (std::min)(delay * 2, static_cast<DWORD>(250));
    }
    return false;
  }

  void ServeConnection(HANDLE pipe) {
    v8host::PeerAuthPolicy policy = {};
    policy.peer_side = v8host::PeerSide::kPipeClient;
    policy.mode = mode_;
    policy.expected_sid = sid_;
    policy.expected_session = session_;
    policy.install_root = payload_.install_root;
    v8host::HeldProcess peer;
    DWORD error = ERROR_SUCCESS;
    const bool authenticated =
        v8host::AuthenticatePipePeer(pipe, policy, &peer, &error);
    if (!authenticated)
      printf("[v8host] client authentication failed category=%lu\n", error);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      --setup_count_;
      if (authenticated) {
        ++connection_count_;
        owner_seen_ = true;
      }
    }
    if (authenticated) {
      // Contract B §8.2: the first post-auth frame must be HELLO with zero
      // addressing ids and a nonzero request id. Malformed or unexpected input
      // fails closed — no reply — and falls through to teardown below.
      uint8_t buffer[512] = {};
      DWORD len = 0;
      protocol::FrameHeader hello_header;
      const uint8_t* payload = nullptr;
      size_t payload_size = 0;
      protocol::HelloPayload hello_payload;
      if (ReadFrameMessage(pipe, buffer, sizeof(buffer), &len, 2000) &&
          protocol::DecodeAndValidateFrame(buffer, len, &hello_header, &payload,
                                           &payload_size) ==
              protocol::DecodeStatus::kOk &&
          hello_header.type == protocol::MessageType::HELLO &&
          hello_header.conn_id == 0 && hello_header.session_id == 0 &&
          hello_header.run_id == 0 && hello_header.request_id != 0 &&
          protocol::DecodeHelloPayload(payload, payload_size, &hello_payload)) {
        const uint32_t conn_id = next_conn_id_.fetch_add(1);
        protocol::BrokerCapabilities caps;
        caps.endpoint_mode = static_cast<uint32_t>(mode_);
        protocol::NegotiationResult negotiation =
            protocol::NegotiateHello(hello_header, hello_payload, caps, conn_id);
        IoWithDeadline(pipe, true, negotiation.frame.data(),
                       static_cast<DWORD>(negotiation.frame.size()), 2000);
      }
    }
    ::FlushFileBuffers(pipe);
    ::DisconnectNamedPipe(pipe);
    ::CloseHandle(pipe);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (authenticated)
        --connection_count_;
      if (authenticated && mode_ == v8host::BrokerMode::kDedicated)
        draining_ = true;
    }
  }

  const sbox_broker_start* start_;
  v8host::PayloadIdentity payload_;
  std::vector<uint8_t> sid_;
  LUID session_;
  v8host::BrokerMode mode_;
  PipeSecurity security_;
  std::mutex mutex_;
  std::vector<HANDLE> tasks_;
  size_t setup_count_ = 0;
  size_t connection_count_ = 0;
  bool owner_seen_ = false;
  std::atomic<bool> draining_{false};
  // Process-unique, nonzero, monotonic connection id (design §8.3: never reused
  // within this broker process).
  std::atomic<uint32_t> next_conn_id_{1};
};

#if defined(SBOX_DEV_ALLOW_UNSIGNED)
// Dev-only exercise of the host-provided sbox_broker_api ownership contract,
// selected by the V8HOST_BROKER_API_TEST environment variable and compiled out
// of release builds. First it proves argument rejection (no spawn). Then
// "ownership" runs a clean spawn / post / idempotent-close / single-wait cycle
// and returns ok (exit 0). "leak" spawns and intentionally abandons a worker so
// the generic host's post-run cleanup must close/wait it and report the breach.
sbox_status RunBrokerApiOwnershipTest(sbox_broker broker,
                                      const sbox_broker_api* api,
                                      const wchar_t* mode) {
  sbox_broker_worker worker = nullptr;
  int32_t exit_code = 0;
  const std::vector<uint8_t> oversize(64 * 1024 + 1, 0);
  if (api->configure_and_spawn(nullptr, nullptr, 0, nullptr, nullptr,
                               &worker) != sbox_error_args ||
      api->configure_and_spawn(broker, nullptr, 0, nullptr, nullptr, nullptr) !=
          sbox_error_args ||
      api->configure_and_spawn(broker, oversize.data(), oversize.size(),
                               nullptr, nullptr, &worker) != sbox_error_args ||
      api->post_message(nullptr, sbox_msg_string, "x", 1) != sbox_error_args ||
      api->close(nullptr) != sbox_error_args ||
      api->wait(nullptr, &exit_code) != sbox_error_args)
    return sbox_error;

  if (mode[0] == L'l') {  // "leak": abandon a spawned worker for host cleanup.
    worker = nullptr;
    if (api->configure_and_spawn(broker, nullptr, 0, nullptr, nullptr,
                                 &worker) != sbox_ok ||
        !worker)
      return sbox_error;
    return sbox_ok;
  }

  worker = nullptr;
  if (api->configure_and_spawn(broker, nullptr, 0, nullptr, nullptr, &worker) !=
          sbox_ok ||
      !worker)
    return sbox_error;
  api->post_message(worker, sbox_msg_string, "ping", 4);
  if (api->close(worker) != sbox_ok || api->close(worker) != sbox_ok)
    return sbox_error;  // close is idempotent
  if (api->wait(worker, &exit_code) != sbox_ok)
    return sbox_error;  // single destructive wait
  return sbox_ok;
}
#endif  // SBOX_DEV_ALLOW_UNSIGNED

}  // namespace

sbox_status V8HostBrokerRun(sbox_broker broker,
                            const sbox_broker_api* api,
                            const sbox_broker_start* start) {
#if defined(SBOX_DEV_ALLOW_UNSIGNED)
  wchar_t test_mode[16] = {};
  if (::GetEnvironmentVariableW(L"V8HOST_BROKER_API_TEST", test_mode, 16) > 0 &&
      broker && api && api->struct_size >= sizeof(*api) &&
      api->configure_and_spawn && api->post_message && api->close && api->wait)
    return RunBrokerApiOwnershipTest(broker, api, test_mode);
#endif
  if (!broker || !api || api->struct_size < sizeof(*api) ||
      !api->configure_and_spawn || !api->post_message || !api->close ||
      !api->wait || !start || start->struct_size < sizeof(*start) ||
      !start->endpoint_name || !start->container_sha256 ||
      !start->plugin_sha256 || !start->container_final_path ||
      !start->plugin_final_path ||
      (start->mode != sbox_broker_mode_shared &&
       start->mode != sbox_broker_mode_dedicated))
    return sbox_error_args;

  DWORD error = ERROR_SUCCESS;
  v8host::PayloadIdentity payload;
  if (!v8host::OpenImmutableFile(start->container_final_path,
                                 &payload.container, &error) ||
      !v8host::OpenImmutableFile(start->plugin_final_path, &payload.plugin,
                                 &error) ||
      payload.container.machine() != start->native_machine ||
      payload.plugin.machine() != start->native_machine ||
      std::memcmp(payload.container.sha256().data(), start->container_sha256,
                  32) != 0 ||
      std::memcmp(payload.plugin.sha256().data(), start->plugin_sha256, 32) !=
          0 ||
      !v8host::TrustAllowed(v8host::VerifyTrust(payload.container)) ||
      !v8host::TrustAllowed(v8host::VerifyTrust(payload.plugin)) ||
      !v8host::ComputePluginSetId(
          start->native_machine, payload.container.sha256(),
          payload.plugin.sha256(), &payload.plugin_set_id))
    return sbox_error;
  payload.native_machine = start->native_machine;
  if (!v8host::DeriveInstallRoot(payload.container.final_path(),
                                 payload.native_machine, &payload.install_root))
    return sbox_error;
  std::vector<uint8_t> sid;
  LUID session = {};
  if (!v8host::QueryCurrentSidAndSession(&sid, &session, &error))
    return sbox_error;
  std::array<uint8_t, 16> nonce = {};
  const std::array<uint8_t, 16>* nonce_ptr = nullptr;
  if (start->mode == sbox_broker_mode_dedicated) {
    if (!start->dedicated_nonce || start->dedicated_nonce_size != nonce.size())
      return sbox_error_args;
    std::memcpy(nonce.data(), start->dedicated_nonce, nonce.size());
    nonce_ptr = &nonce;
  }
  std::wstring expected_endpoint;
  std::array<uint8_t, 32> endpoint_key = {};
  if (!v8host::DeriveEndpoint(
          sid, payload.plugin_set_id,
          start->mode == sbox_broker_mode_shared
              ? v8host::BrokerMode::kShared
              : v8host::BrokerMode::kDedicated,
          nonce_ptr, &expected_endpoint, &endpoint_key) ||
      expected_endpoint != start->endpoint_name)
    return sbox_error;
  printf("[v8host] broker endpoint=%s mode=%s pid=%lu\n",
         v8host::HexPrefix(endpoint_key, 6).c_str(),
         start->mode == sbox_broker_mode_shared ? "shared" : "dedicated",
         ::GetCurrentProcessId());
  return BrokerService(start, std::move(payload), std::move(sid), session).Run();
}
