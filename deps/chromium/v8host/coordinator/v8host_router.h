// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#ifndef V8HOST_COORDINATOR_V8HOST_ROUTER_H_
#define V8HOST_COORDINATOR_V8HOST_ROUTER_H_

#include "sbox.h"
#include "v8host_file_identity.h"
#include "v8host_peer_auth.h"
#include "v8host_protocol_messages.h"
#include "v8host_run_envelope.h"
#include "v8host_spawn_config.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#if defined(V8HOST_ROUTER_TESTING)
#include <functional>
#endif

namespace v8host::coordinator {
namespace protocol = v8host::protocol;
enum class ConnState { kAuthenticating, kNegotiating, kOpen, kClosing, kClosed };
enum class SessionState {
  kCreating,
  kLogicalReady,
  kBindingProfile,
  kStartingWorker,
  kStartupReady,
  kSecurityReady,
  kOpen,
  kClosing,
  kClosed
};
enum class WorkerState { kNone, kSpawning, kWarming, kLockedDown, kRunning, kCloseRequested, kWaiting, kReaped };
enum class RunState {
  kCreated,
  kStartPending,
  kActive,
  kCancelRequested,
  kCompleted,
  kFailed,
  kCancelled,
  kBrokerLost,
  kWorkerExited
};
inline bool IsTerminal(RunState s) {
  return s >= RunState::kCompleted;
}
struct Connection;
struct Session;
class Router;
using SessionConfig = protocol::CreateSessionPayload;
struct BoundProfile {
  int32_t effective_tier = 0;
  std::string engine_dll;
  std::string snapshot_path;
  bool prohibit_dynamic_code = false;
};
struct Run {
  uint32_t run_id = 0;
  std::atomic<RunState> state{RunState::kCreated};
  uint32_t queued_relay_bytes = 0;
  Session *session = nullptr;
  protocol::StatusCode error = protocol::StatusCode::ERROR_INTERNAL;
  std::vector<uint8_t> guest;
  std::deque<std::vector<uint8_t>> held_relays;
  bool TryTerminal(RunState desired);
};
struct Worker {
  struct Fact {
    sbox_msg_kind kind = sbox_msg_binary;
    size_t size = 0;
    std::array<uint8_t, protocol::kMaxFramePayload> data;
  };
  Session *session = nullptr;
  const sbox_broker_api *api = nullptr;
  HANDLE cleanup = nullptr;
  // One core reader produces; the connection strand consumes. Counters wrap unsigned.
  static_assert(std::atomic<size_t>::is_always_lock_free);
  std::atomic<bool> mailbox_failed{false};
  std::array<Fact, 16> mailbox;
  std::atomic<size_t> mailbox_head{0}, mailbox_tail{0};
#if defined(V8HOST_ROUTER_TESTING)
  std::function<void()> mailbox_readout;
#endif
  uint32_t engine_busy_run_id = 0;
  bool startup = false, security = false;
  static void SBOX_CALL OnMessage(void *, sbox_msg_kind, const void *, size_t);
  static DWORD WINAPI Reap(void *);
  sbox_broker_worker handle = nullptr;
  std::atomic<WorkerState> state{WorkerState::kNone};
  bool close_called = false;
  bool wait_called = false;
  HeldFile engine_image;
  uint32_t active_run_id = 0;
  std::deque<uint32_t> pending_run_ids;
};
struct Session {
  uint32_t session_id = 0;
  Connection *conn = nullptr;
  // State and worker publication are strand-owned after admission.
  SessionState state = SessionState::kCreating;
  SessionConfig config;
  uint32_t highest_run_id = 0;
  bool profile_bound = false;
  BoundProfile profile;
  std::unique_ptr<Worker> worker;
  std::mutex mutex;
  std::unordered_map<uint32_t, std::unique_ptr<Run>> runs;
  // Retain removed objects until their contenders have joined.
  std::vector<std::unique_ptr<Run>> retired_runs;
#if defined(V8HOST_ROUTER_TESTING)
  std::function<void()> terminal_removed;
#endif
};
struct Connection {
  Connection();
  ~Connection();
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  HeldProcess peer;
  uint32_t conn_id = 0;
  uint16_t version_minor = protocol::kWireVersionMinor;
  ConnState state = ConnState::kAuthenticating;
  protocol::RequestCache request_cache;
  // Lock order: connection, session, output. Callbacks never take these locks.
  std::mutex mutex;
  std::unordered_map<uint32_t, std::unique_ptr<Session>> sessions;
  uint32_t highest_session_id = 0;
  std::vector<std::unique_ptr<Session>> retired_sessions;
  std::mutex out_mutex;
  std::deque<std::vector<uint8_t>> out_queue;
  uint32_t out_control_bytes = 0;
  uint32_t out_control_requests = 0;
  uint64_t out_relay_bytes = 0;
  HANDLE out_wake = nullptr;
  HANDLE stop = nullptr;
  HANDLE worker_wake = nullptr;
  Router *dispatcher = nullptr;
  bool Enqueue(std::vector<uint8_t> frame);
  bool TakeOutput(std::vector<uint8_t> *frame);
  void CompleteOutput(size_t bytes);
  bool DrainOutput(DWORD timeout_ms);
  void Stop();
  bool StartWriter();
  void JoinWriter();
  bool ReadFrame(uint8_t *buffer, DWORD capacity, DWORD *size, DWORD timeout_ms);
#if defined(V8HOST_ROUTER_TESTING)
  HANDLE read_pending = nullptr;
  HANDLE write_pending = nullptr;
  HANDLE writer_release = nullptr;
  std::atomic<uint32_t> active_io{0};
  std::atomic<uint32_t> inline_reads{0};
  std::atomic<uint32_t> writers_started{0};
  std::atomic<uint32_t> writers_joined{0};
#endif
 private:
  static DWORD WINAPI WriteTask(void *context);
  std::condition_variable out_drained_;
  HANDLE writer_ = nullptr;
};

bool EnvelopeFits(v8host::RunEnvelopeType type, size_t payload_size);
bool ValidateSessionConfig(const SessionConfig &config, BrokerMode mode);
bool PrepareProfile(
    const SessionConfig &config,
    const protocol::StartRunPayload &inputs,
    const std::wstring &payload_directory,
    BoundProfile *out);
protocol::StatusCode BindProfile(Session &session, const BoundProfile &profile);
bool PrepareSpawnConfig(const SessionConfig &config, const BoundProfile &profile, std::vector<uint8_t> *out);
class Router {
 public:
  explicit Router(
      BrokerMode mode,
      sbox_broker broker = nullptr,
      const sbox_broker_api *api = nullptr,
      std::wstring payload_directory = L"",
      uint16_t machine = 0)
      : mode_(mode), broker_(broker), api_(api), payload_directory_(std::move(payload_directory)), machine_(machine) {}
  void Pump(Connection &conn);
  bool Route(Connection &conn, const uint8_t *data, size_t size);
  void Close(Connection &conn);

 private:
  bool Spawn(Session &session);
  bool Post(Session &session, const std::vector<uint8_t> &bytes);
  void Dispatch(Session &session);
  void CloseSession(Connection &conn, uint32_t id, RunState terminal);
  void Reclaim(Connection &conn, bool join);
  BrokerMode mode_;
  sbox_broker broker_;
  const sbox_broker_api *api_;
  std::wstring payload_directory_;
  uint16_t machine_;
};
} // namespace v8host::coordinator
#endif // V8HOST_COORDINATOR_V8HOST_ROUTER_H_
