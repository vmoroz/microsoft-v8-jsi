#include "v8host_test_support.h"

#include "v8host_broker_rendezvous.h"
#include "v8host_file_identity.h"
#include "v8host_payload_identity.h"
#include "v8host_peer_auth.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

using v8host::BrokerConnection;
using v8host::BrokerMode;
using v8host::BrokerRendezvous;
using v8host::ProbeResult;
using v8host::RendezvousStatus;
using v8host::test::ExecutableDirectory;

bool ConnectAndProbe(BrokerMode mode,
                     uint32_t sequence,
                     BrokerConnection* connection,
                     ProbeResult* result,
                     std::string* detail) {
  BrokerRendezvous rendezvous(ExecutableDirectory(), mode);
  const RendezvousStatus connected = rendezvous.ConnectOrLaunch(connection);
  if (connected != RendezvousStatus::kOk) {
    *detail = "connect status=" + std::to_string(static_cast<int>(connected));
    return false;
  }
  const RendezvousStatus probed = connection->Probe(sequence, result);
  if (probed != RendezvousStatus::kOk ||
      result->observed_client_pid != ::GetCurrentProcessId() ||
      result->sequence != sequence) {
    *detail = "probe status=" + std::to_string(static_cast<int>(probed));
    return false;
  }
  return true;
}

bool SharedFanIn(std::string* detail) {
  constexpr size_t kClients = 16;
  std::array<DWORD, kClients> pids = {};
  std::array<bool, kClients> passed = {};
  std::array<std::string, kClients> details;
  std::vector<std::thread> threads;
  for (size_t i = 0; i < kClients; ++i) {
    threads.emplace_back([&, i] {
      BrokerConnection connection;
      ProbeResult result;
      passed[i] = ConnectAndProbe(BrokerMode::kShared,
                                  static_cast<uint32_t>(i + 1), &connection,
                                  &result, &details[i]);
      pids[i] = result.broker_pid;
    });
  }
  for (std::thread& thread : threads)
    thread.join();
  if (!std::all_of(passed.begin(), passed.end(), [](bool value) {
        return value;
      })) {
    for (size_t i = 0; i < kClients; ++i) {
      if (!passed[i]) {
        *detail = "client " + std::to_string(i) + ": " + details[i];
        break;
      }
    }
    return false;
  }
  std::set<DWORD> unique(pids.begin(), pids.end());
  if (unique.size() != 1 || *unique.begin() == 0) {
    *detail = "clients observed multiple broker PIDs";
    return false;
  }
  printf("endpoint fan-in broker pid=%lu clients=%zu\n", *unique.begin(),
         kClients);
  return true;
}

bool ExactPayloadSeparation(std::string* detail) {
  std::vector<uint8_t> sid;
  LUID session = {};
  DWORD error = ERROR_SUCCESS;
  if (!v8host::QueryCurrentSidAndSession(&sid, &session, &error))
    return false;
  std::array<uint8_t, 32> first = {};
  std::array<uint8_t, 32> second = {};
  second[0] = 1;
  std::wstring first_endpoint;
  std::wstring second_endpoint;
  std::array<uint8_t, 32> first_key = {};
  std::array<uint8_t, 32> second_key = {};
  const bool ok =
      v8host::DeriveEndpoint(sid, first, BrokerMode::kShared, nullptr,
                             &first_endpoint, &first_key) &&
      v8host::DeriveEndpoint(sid, second, BrokerMode::kShared, nullptr,
                             &second_endpoint, &second_key) &&
      first_endpoint != second_endpoint;
  if (!ok)
    *detail = "alternate payload digest did not separate endpoint";
  return ok;
}

bool DedicatedUnique(std::string* detail) {
  BrokerConnection first;
  BrokerConnection second;
  ProbeResult first_result;
  ProbeResult second_result;
  if (!ConnectAndProbe(BrokerMode::kDedicated, 101, &first, &first_result,
                       detail) ||
      !ConnectAndProbe(BrokerMode::kDedicated, 102, &second, &second_result,
                       detail))
    return false;
  if (first.endpoint() == second.endpoint() ||
      first_result.broker_pid == second_result.broker_pid) {
    *detail = "dedicated endpoint or PID reused";
    return false;
  }
  return true;
}

bool MixedMode(std::string* detail) {
  BrokerConnection shared;
  BrokerConnection first;
  BrokerConnection second;
  ProbeResult shared_result;
  ProbeResult first_result;
  ProbeResult second_result;
  if (!ConnectAndProbe(BrokerMode::kShared, 201, &shared, &shared_result,
                       detail) ||
      !ConnectAndProbe(BrokerMode::kDedicated, 202, &first, &first_result,
                       detail) ||
      !ConnectAndProbe(BrokerMode::kDedicated, 203, &second, &second_result,
                       detail))
    return false;
  std::set<DWORD> pids = {shared_result.broker_pid, first_result.broker_pid,
                          second_result.broker_pid};
  if (pids.size() != 3) {
    *detail = "mixed brokers did not isolate PIDs";
    return false;
  }
  return true;
}

bool IdleExitRelaunch(std::string* detail) {
  BrokerConnection connection;
  ProbeResult first;
  if (!ConnectAndProbe(BrokerMode::kShared, 301, &connection, &first, detail))
    return false;
  connection.Close();
  const ULONGLONG start = ::GetTickCount64();
  if (!v8host::test::WaitForProcessExit(first.broker_pid, 8000) ||
      ::GetTickCount64() - start < 4900) {
    *detail = "broker did not honor five-second idle grace";
    return false;
  }
  BrokerConnection replacement;
  ProbeResult second;
  if (!ConnectAndProbe(BrokerMode::kShared, 302, &replacement, &second, detail))
    return false;
  if (first.broker_pid == second.broker_pid) {
    *detail = "broker PID did not change after relaunch";
    return false;
  }
  return true;
}

bool GraceCancel(std::string* detail) {
  BrokerConnection first_connection;
  ProbeResult first;
  if (!ConnectAndProbe(BrokerMode::kShared, 401, &first_connection, &first,
                       detail))
    return false;
  first_connection.Close();
  ::Sleep(1500);
  BrokerConnection second_connection;
  ProbeResult second;
  if (!ConnectAndProbe(BrokerMode::kShared, 402, &second_connection, &second,
                       detail))
    return false;
  if (first.broker_pid != second.broker_pid) {
    *detail = "connection during grace did not preserve broker";
    return false;
  }
  return true;
}

struct SquatterState {
  std::wstring endpoint;
  HANDLE ready = nullptr;
  std::atomic<DWORD> bytes{0};
};

void Squatter(SquatterState* state) {
  HANDLE pipe = ::CreateNamedPipeW(
      state->endpoint.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1, 256, 256, 0, nullptr);
  ::SetEvent(state->ready);
  if (pipe == INVALID_HANDLE_VALUE)
    return;
  if (::ConnectNamedPipe(pipe, nullptr) ||
      ::GetLastError() == ERROR_PIPE_CONNECTED) {
    char byte = 0;
    DWORD read = 0;
    if (::ReadFile(pipe, &byte, 1, &read, nullptr))
      state->bytes = read;
  }
  ::CloseHandle(pipe);
}

bool EndpointSquatter(std::string* detail) {
  BrokerRendezvous rendezvous(ExecutableDirectory(), BrokerMode::kShared);
  BrokerConnection warmup;
  const RendezvousStatus init = rendezvous.ConnectOrLaunch(&warmup);
  if (init != RendezvousStatus::kOk)
    return false;
  ProbeResult response;
  if (warmup.Probe(501, &response) != RendezvousStatus::kOk)
    return false;
  warmup.Close();
  if (!v8host::test::WaitForProcessExit(response.broker_pid, 8000))
    return false;

  SquatterState state;
  state.endpoint = rendezvous.endpoint();
  state.ready = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
  std::thread squatter(Squatter, &state);
  ::WaitForSingleObject(state.ready, 2000);
  BrokerConnection connection;
  const RendezvousStatus status = rendezvous.ConnectOrLaunch(&connection);
  if (connection.pipe() != INVALID_HANDLE_VALUE)
    connection.Close();
  squatter.join();
  ::CloseHandle(state.ready);
  const bool ok = status == RendezvousStatus::kPeerAuthenticationFailed &&
                  state.bytes.load() == 0;
  if (!ok)
    *detail = "squatter was not rejected before client write";
  return ok;
}

bool ImmutableWrite(std::string* detail) {
  v8host::HeldFile held;
  DWORD error = ERROR_SUCCESS;
  const std::wstring path = ExecutableDirectory() + L"\\sbox.exe";
  if (!v8host::OpenImmutableFile(path, &held, &error))
    return false;
  HANDLE writer =
      ::CreateFileW(path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (writer != INVALID_HANDLE_VALUE) {
    ::CloseHandle(writer);
    *detail = "write sharing succeeded while immutable handle held";
    return false;
  }
  HANDLE deleter =
      ::CreateFileW(path.c_str(), DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (deleter != INVALID_HANDLE_VALUE) {
    ::CloseHandle(deleter);
    *detail = "delete sharing succeeded while immutable handle held";
    return false;
  }
  return true;
}

bool MutablePreexisting(std::string* detail) {
  const std::wstring path = ExecutableDirectory() + L"\\sbox.exe";
  HANDLE writer =
      ::CreateFileW(path.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (writer == INVALID_HANDLE_VALUE) {
    *detail = "could not establish mutable preexisting handle";
    return false;
  }
  v8host::HeldFile held;
  DWORD error = ERROR_SUCCESS;
  const bool rejected = !v8host::OpenImmutableFile(path, &held, &error);
  ::CloseHandle(writer);
  if (!rejected)
    *detail = "immutable open accepted mutable preexisting sharing";
  return rejected;
}

bool PathPolicy(std::string* detail) {
  const bool ok =
      v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                 L"\\\\?\\Volume{a}\\root\\client.exe") &&
      !v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                  L"\\\\?\\Volume{a}\\root2\\client.exe") &&
      !v8host::IsStrictDescendant(L"\\\\?\\Volume{a}\\root",
                                  L"\\\\?\\Volume{b}\\root\\client.exe");
  if (!ok)
    *detail = "component-aware canonical root policy failed";
  return ok;
}

bool DedicatedOwnerExit(std::string* detail) {
  BrokerConnection connection;
  ProbeResult result;
  if (!ConnectAndProbe(BrokerMode::kDedicated, 601, &connection, &result,
                       detail))
    return false;
  connection.Close();
  if (!v8host::test::WaitForProcessExit(result.broker_pid, 3000)) {
    *detail = "dedicated broker did not join and exit";
    return false;
  }
  return true;
}

bool DisconnectRaces(std::string* detail) {
  for (uint32_t i = 0; i < 64; ++i) {
    BrokerConnection connection;
    ProbeResult result;
    if (!ConnectAndProbe(BrokerMode::kShared, 700 + i, &connection, &result,
                         detail))
      return false;
    connection.Close();
  }
  return true;
}

bool NoGenericClientRole(std::string* detail) {
  DWORD exit_code = 0;
  const std::wstring command =
      L"\"" + ExecutableDirectory() + L"\\sbox.exe\" --client";
  if (!v8host::test::RunProcess(command, &exit_code) || exit_code != 2) {
    *detail = "generic host accepted removed client role";
    return false;
  }
  return true;
}

bool TrustPolicy(std::string* detail) {
  const bool ok = v8host::TrustAllowed(v8host::TrustStatus::kUnsigned) &&
                  !v8host::TrustAllowed(v8host::TrustStatus::kInvalid) &&
                  !v8host::TrustAllowed(v8host::TrustStatus::kError);
  if (!ok)
    *detail = "development trust policy accepted invalid signature";
  return ok;
}

// ===== peer authentication unit coverage =====
//
// A connected message-mode pipe pair in this process makes the current
// (same-user, trusted, installed) process the authenticated peer. Negative
// cases mutate one policy field, or inject scripted identity facts via
// PeerAuthHooks for the fail-closed paths (PID reread, per-step query failure)
// that a stable local pipe cannot reproduce.
struct SelfPeer {
  HANDLE server = INVALID_HANDLE_VALUE;
  HANDLE client = INVALID_HANDLE_VALUE;
  v8host::HeldFile image;
  std::vector<uint8_t> sid;
  LUID session = {};
  ~SelfPeer() {
    if (client != INVALID_HANDLE_VALUE)
      ::CloseHandle(client);
    if (server != INVALID_HANDLE_VALUE)
      ::CloseHandle(server);
  }
};

bool MakeSelfPeer(SelfPeer* peer) {
  const std::wstring name = L"\\\\.\\pipe\\v8host-authtest-" +
                            std::to_wstring(::GetCurrentProcessId()) + L"-" +
                            std::to_wstring(::GetTickCount64());
  peer->server = ::CreateNamedPipeW(
      name.c_str(), PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 256, 256, 0,
      nullptr);
  if (peer->server == INVALID_HANDLE_VALUE)
    return false;
  peer->client = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                               nullptr, OPEN_EXISTING, 0, nullptr);
  if (peer->client == INVALID_HANDLE_VALUE)
    return false;
  ::ConnectNamedPipe(peer->server, nullptr);
  std::wstring self(32768, L'\0');
  const DWORD n = ::GetModuleFileNameW(nullptr, self.data(),
                                       static_cast<DWORD>(self.size()));
  self.resize(n);
  DWORD error = 0;
  return v8host::OpenImmutableFile(self, &peer->image, &error) &&
         v8host::QueryCurrentSidAndSession(&peer->sid, &peer->session, &error);
}

v8host::PeerAuthPolicy BasePolicy(const SelfPeer& peer, v8host::BrokerMode mode) {
  v8host::PeerAuthPolicy policy = {};
  policy.peer_side = v8host::PeerSide::kPipeClient;
  policy.mode = mode;
  policy.expected_sid = peer.sid;
  policy.expected_session = peer.session;
  policy.install_root = v8host::ParentPath(peer.image.final_path());
  policy.expected_image = &peer.image;
  return policy;
}

bool Authenticates(const SelfPeer& peer,
                   const v8host::PeerAuthPolicy& policy,
                   const v8host::PeerAuthHooks* hooks = nullptr) {
  v8host::HeldProcess out;
  DWORD error = ERROR_SUCCESS;
  return v8host::AuthenticatePipePeer(peer.server, policy, &out, &error, hooks);
}

bool AuthSameUserPositive(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "pipe/identity setup failed";
    return false;
  }
  if (!Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared))) {
    *detail = "correct same-user co-located policy was rejected";
    return false;
  }
  return true;
}

bool AuthCrossUserReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  std::vector<uint8_t> other(SECURITY_MAX_SID_SIZE);
  DWORD size = SECURITY_MAX_SID_SIZE;
  if (!::CreateWellKnownSid(WinWorldSid, nullptr, other.data(), &size)) {
    *detail = "could not build alternate SID";
    return false;
  }
  other.resize(size);
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_sid = other;
  if (Authenticates(peer, policy)) {
    *detail = "different-user SID was accepted";
    return false;
  }
  return true;
}

bool AuthWrongSessionReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_session.LowPart ^= 0x5a5a5a5a;
  if (Authenticates(peer, policy)) {
    *detail = "different logon session was accepted";
    return false;
  }
  return true;
}

bool AuthWrongPayloadImageReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::HeldFile other;
  DWORD error = 0;
  if (!v8host::OpenImmutableFile(ExecutableDirectory() + L"\\v8host.dll", &other,
                                 &error)) {
    *detail = "could not open alternate image";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.expected_image = &other;
  if (Authenticates(peer, policy)) {
    *detail = "wrong expected payload image was accepted";
    return false;
  }
  return true;
}

bool AuthNonColocatedReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.install_root =
      L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\elsewhere";
  if (Authenticates(peer, policy)) {
    *detail = "non-co-located client accepted in shared mode";
    return false;
  }
  return true;
}

bool AuthSiblingPrefixReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.install_root = v8host::ParentPath(peer.image.final_path()) + L"2";
  if (Authenticates(peer, policy)) {
    *detail = "sibling-prefix root accepted as ancestor";
    return false;
  }
  return true;
}

bool AuthDedicatedNonColocatedPositive(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthPolicy policy =
      BasePolicy(peer, v8host::BrokerMode::kDedicated);
  policy.install_root =
      L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\elsewhere";
  if (!Authenticates(peer, policy)) {
    *detail = "dedicated mode rejected a same-user non-co-located peer";
    return false;
  }
  return true;
}

bool AuthLaunchMismatchReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  std::wstring command =
      L"\"" + ExecutableDirectory() + L"\\sbox.exe\" --client";
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process = {};
  if (!::CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &process)) {
    *detail = "could not launch mismatch helper";
    return false;
  }
  ::CloseHandle(process.hThread);
  v8host::PeerAuthPolicy policy = BasePolicy(peer, v8host::BrokerMode::kShared);
  policy.launched_process = process.hProcess;
  const bool accepted = Authenticates(peer, policy);
  ::WaitForSingleObject(process.hProcess, 5000);
  ::CloseHandle(process.hProcess);
  if (accepted) {
    *detail = "launch-instance mismatch was accepted";
    return false;
  }
  return true;
}

bool AuthPidRereadMismatchReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  const DWORD real = ::GetCurrentProcessId();
  auto calls = std::make_shared<int>(0);
  v8host::PeerAuthHooks hooks;
  hooks.read_peer_pid = [real, calls](HANDLE, v8host::PeerSide, DWORD* pid) {
    *pid = (++*calls == 1) ? real : real + 1;
    return true;
  };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "peer PID reread mismatch was accepted";
    return false;
  }
  return true;
}

bool AuthQueryFailureReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthHooks hooks;
  hooks.query_identity = [](DWORD, v8host::HeldProcess*, DWORD* error) {
    if (error)
      *error = ERROR_ACCESS_DENIED;
    return false;
  };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "identity query failure was accepted";
    return false;
  }
  return true;
}

bool AuthPidReadFailureReject(std::string* detail) {
  SelfPeer peer;
  if (!MakeSelfPeer(&peer)) {
    *detail = "setup failed";
    return false;
  }
  v8host::PeerAuthHooks hooks;
  hooks.read_peer_pid = [](HANDLE, v8host::PeerSide, DWORD*) { return false; };
  if (Authenticates(peer, BasePolicy(peer, v8host::BrokerMode::kShared),
                    &hooks)) {
    *detail = "peer PID read failure was accepted";
    return false;
  }
  return true;
}

bool AuthInvalidPipeReject(std::string* detail) {
  v8host::PeerAuthPolicy policy = {};
  policy.peer_side = v8host::PeerSide::kPipeClient;
  policy.mode = v8host::BrokerMode::kShared;
  v8host::HeldProcess out;
  DWORD error = ERROR_SUCCESS;
  if (v8host::AuthenticatePipePeer(INVALID_HANDLE_VALUE, policy, &out, &error)) {
    *detail = "invalid pipe handle authenticated";
    return false;
  }
  return true;
}

// ===== generic-host sbox_broker_api ownership (driven in-broker) =====
//
// Launches the real sbox.exe broker and selects the plugin's dev-only
// sbox_broker_api self-test via an environment variable (no new export). The
// broker exercises argument rejection and the spawn/close/wait ownership cycle
// in-process; "leak" abandons a worker so the generic host's post-run cleanup
// must reclaim it and report the breach (exit 4).
bool RunBrokerApiMode(const wchar_t* mode, DWORD* exit_code) {
  ::SetEnvironmentVariableW(L"V8HOST_BROKER_API_TEST", mode);
  const std::wstring pipe =
      L"\\\\.\\pipe\\v8host-rv1-" + std::wstring(64, L'0');
  const std::wstring command = L"\"" + ExecutableDirectory() +
                               L"\\sbox.exe\" --broker --mode=shared --pipe=" +
                               pipe + L" --plugin v8host.dll";
  const bool ok = v8host::test::RunProcess(command, exit_code);
  ::SetEnvironmentVariableW(L"V8HOST_BROKER_API_TEST", nullptr);
  return ok;
}

bool BrokerApiOwnership(std::string* detail) {
  DWORD code = 0xFFFFFFFF;
  if (!RunBrokerApiMode(L"ownership", &code)) {
    *detail = "ownership broker launch failed";
    return false;
  }
  if (code != 0) {
    *detail = "sbox_broker_api ownership checks failed, exit=" +
              std::to_string(code);
    return false;
  }
  return true;
}

bool BrokerApiLeakedCleanup(std::string* detail) {
  DWORD code = 0xFFFFFFFF;
  if (!RunBrokerApiMode(L"leak", &code)) {
    *detail = "leak broker launch failed";
    return false;
  }
  if (code != 4) {
    *detail = "host did not reclaim leaked worker (expected exit 4), exit=" +
              std::to_string(code);
    return false;
  }
  return true;
}

// Post-verification rename and in-place replacement of a held image must fail
// for the handle's whole lifetime (staged on a throwaway copy, not a live
// binary). Open-for-write and open-for-delete denial are covered by
// immutable-write; this adds the rename and replace mutation variants.
bool ImmutableMutation(std::string* detail) {
  wchar_t temp_dir[MAX_PATH] = {};
  if (!::GetTempPathW(MAX_PATH, temp_dir)) {
    *detail = "temp path query failed";
    return false;
  }
  const std::wstring held_path = std::wstring(temp_dir) + L"v8host-immutable-" +
                                 std::to_wstring(::GetCurrentProcessId()) +
                                 L".bin";
  const std::wstring rename_target = held_path + L".moved";
  if (!::CopyFileW((ExecutableDirectory() + L"\\sbox.exe").c_str(),
                   held_path.c_str(), FALSE)) {
    *detail = "could not stage held file copy";
    return false;
  }
  bool ok = true;
  {
    v8host::HeldFile held;
    DWORD error = 0;
    if (!v8host::OpenImmutableFile(held_path, &held, &error)) {
      ::DeleteFileW(held_path.c_str());
      *detail = "could not open staged copy immutably";
      return false;
    }
    if (::MoveFileExW(held_path.c_str(), rename_target.c_str(),
                      MOVEFILE_REPLACE_EXISTING)) {
      ::MoveFileExW(rename_target.c_str(), held_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING);
      ok = false;
      *detail = "rename succeeded while immutable handle held";
    }
    if (ok) {
      HANDLE replace = ::CreateFileW(
          held_path.c_str(), GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (replace != INVALID_HANDLE_VALUE) {
        ::CloseHandle(replace);
        ok = false;
        *detail = "in-place replace succeeded while immutable handle held";
      }
    }
  }
  ::DeleteFileW(held_path.c_str());
  ::DeleteFileW(rename_target.c_str());
  return ok;
}

// The generic host must reject a resolvable plugin whose vtable reports the
// wrong ABI version / null entries before driving any lifecycle (exit 3).
bool HostRejectsBadPluginAbi(std::string* detail) {
  const std::wstring pipe =
      L"\\\\.\\pipe\\v8host-rv1-" + std::wstring(64, L'0');
  const std::wstring command = L"\"" + ExecutableDirectory() +
                               L"\\sbox.exe\" --broker --mode=shared --pipe=" +
                               pipe + L" --plugin v8host_fake_plugin.dll";
  DWORD code = 0;
  if (!v8host::test::RunProcess(command, &code)) {
    *detail = "bad-plugin broker launch failed";
    return false;
  }
  if (code != 3) {
    *detail =
        "host did not reject invalid plugin ABI (expected exit 3), exit=" +
        std::to_string(code);
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<v8host::test::TestCase> tests = {
      {"rendezvous", "shared-fan-in", SharedFanIn},
      {"rendezvous", "exact-payload-separation", ExactPayloadSeparation},
      {"rendezvous", "dedicated-unique", DedicatedUnique},
      {"rendezvous", "mixed-mode", MixedMode},
      {"rendezvous", "idle-exit-relaunch", IdleExitRelaunch},
      {"rendezvous", "grace-cancel", GraceCancel},
      {"rendezvous", "no-generic-client-role", NoGenericClientRole},
      {"peer-auth", "endpoint-squatter", EndpointSquatter},
      {"peer-auth", "immutable-write", ImmutableWrite},
      {"peer-auth", "mutable-preexisting-sharing", MutablePreexisting},
      {"peer-auth", "immutable-mutation", ImmutableMutation},
      {"peer-auth", "canonical-install-root", PathPolicy},
      {"peer-auth", "compile-time-unsigned-policy", TrustPolicy},
      {"peer-auth", "same-user-positive", AuthSameUserPositive},
      {"peer-auth", "cross-user-reject", AuthCrossUserReject},
      {"peer-auth", "wrong-session-reject", AuthWrongSessionReject},
      {"peer-auth", "wrong-payload-image-reject", AuthWrongPayloadImageReject},
      {"peer-auth", "non-co-located-reject", AuthNonColocatedReject},
      {"peer-auth", "sibling-prefix-reject", AuthSiblingPrefixReject},
      {"peer-auth", "dedicated-non-co-located-positive",
       AuthDedicatedNonColocatedPositive},
      {"peer-auth", "launch-instance-mismatch-reject", AuthLaunchMismatchReject},
      {"peer-auth", "pid-reread-mismatch-reject", AuthPidRereadMismatchReject},
      {"peer-auth", "query-failure-reject", AuthQueryFailureReject},
      {"peer-auth", "pid-read-failure-reject", AuthPidReadFailureReject},
      {"peer-auth", "invalid-pipe-reject", AuthInvalidPipeReject},
      {"lifetime", "dedicated-owner-disconnect", DedicatedOwnerExit},
      {"lifetime", "connect-disconnect-races", DisconnectRaces},
      {"lifetime", "broker-api-ownership", BrokerApiOwnership},
      {"lifetime", "broker-api-leaked-cleanup", BrokerApiLeakedCleanup},
      {"lifetime", "host-rejects-bad-plugin-abi", HostRejectsBadPluginAbi},
  };
  return v8host::test::RunTests(argc, argv, tests);
}
