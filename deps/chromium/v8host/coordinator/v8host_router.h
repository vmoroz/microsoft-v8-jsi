// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#ifndef V8HOST_COORDINATOR_V8HOST_ROUTER_H_
#define V8HOST_COORDINATOR_V8HOST_ROUTER_H_

#include "sbox.h"
#include "v8host_file_identity.h"
#include "v8host_peer_auth.h"
#include "v8host_protocol_messages.h"
#include "v8host_spawn_config.h"

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
  bool TryTerminal(RunState desired);
};
struct Worker {
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
  SessionState state = SessionState::kCreating;
  SessionConfig config;
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
  std::atomic<uint32_t> writers_started{0};
  std::atomic<uint32_t> writers_joined{0};
#endif
 private:
  static DWORD WINAPI WriteTask(void *context);
  std::condition_variable out_drained_;
  HANDLE writer_ = nullptr;
};

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
  explicit Router(BrokerMode mode) : mode_(mode) {}
  bool Route(Connection &conn, const uint8_t *data, size_t size);
  void Close(Connection &conn);

 private:
  BrokerMode mode_;
};
} // namespace v8host::coordinator
#endif // V8HOST_COORDINATOR_V8HOST_ROUTER_H_
