// sbox_main.cc — the product single-image sbox.exe: one binary that is BOTH the
// sandbox broker and the sandbox worker, selected by argv. It statically links
// the same Chromium sandbox core as the DLL did (via sbox_dll.cc) so the broker
// and worker share one image and one set of sandbox globals.
//
// Personas (role is chosen first; neither falls through into the other's init):
//   sbox.exe --broker   : EnsureBroker + spawn "sbox.exe --worker" + round-trip.
//                         Calls ONLY sbox_broker_*.
//   sbox.exe --worker    : sbox_target_begin -> warmup -> lower_token -> run.
//                         Calls ONLY sbox_target_*.
//   sbox.exe --broker-service / --client / --pipe-bench : the shared-broker
//                         rendezvous + a transport-latency probe (used by later
//                         stages).
//
// SBOX_API is plain extern "C" here (the target defines SBOX_STATIC), so the
// sbox_* core compiled into this EXE stays out of its export table.
#include "sbox.h"
#include "sbox_harden.h"
#include "sbox_plugin_abi.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <atomic>
#include <memory>
#include <string>

// Same-image seed: the broker writes this worker's sandbox globals + message
// channel directly at their shared RVAs while the worker is suspended, so there
// is no exported bootstrap struct and no export-table walk. sbox_target_begin
// adopts that seed (and fails closed if its magic is absent).

namespace {

// Worker exit codes (the broker asserts 0). Distinct values make a failed run
// self-describing in the captured worker log.
enum WorkerExit {
  kOk = 0,
  kBeginFailed = 10,
  kPingPreFailed = 11,
  kDllLoadFailed = 12,
  kDllResolveFailed = 13,
  kWarmupFailed = 14,
  kLowerTokenFailed = 15,
  kPingPostFailed = 16,
  kRunFailed = 17,  // payload run failed; rc=3 means ACG was NOT enforced
};

std::wstring SelfPath() {
  wchar_t buf[MAX_PATH] = {};
  const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
  return std::wstring(buf, n);
}

// The broker runs UNRESTRICTED, so it (not the token-restricted worker, which
// cannot reliably reach the crypto/catalog services) verifies the payload chain
// the worker will load. Fail-closed on a tampered/invalid signature; dev builds
// tolerate UNSIGNED only via the compile-time SBOX_DEV_ALLOW_UNSIGNED (no runtime
// bypass). Call before spawning a worker.
bool VerifyPayloadChain() {
  const std::wstring dir = sbox_harden::ExeDir();
  return sbox_harden::CheckTrust(dir + L"v8host.dll", "v8host.dll") &&
         sbox_harden::CheckTrust(dir + L"v8jsisb.dll", "v8jsisb.dll");
}

// --- host services bridge: thin wrappers so v8host.dll uses the sandbox
// message channel WITHOUT linking the sandbox core (see sbox_plugin_abi.h). ---
int HostPost(void* t, int kind, const void* data, size_t len) {
  return sbox_target_post_message(static_cast<SboxTarget*>(t), kind, data, len);
}
void* HostInbound(void* t) {
  return sbox_target_inbound_event(static_cast<SboxTarget*>(t));
}
int HostDrain(void* t, SboxPluginMessageCb cb, void* ctx) {
  return sbox_target_drain_messages(static_cast<SboxTarget*>(t),
                                    reinterpret_cast<SboxMessageCb>(cb), ctx);
}
void* HostClose(void* t) {
  return sbox_target_close_event(static_cast<SboxTarget*>(t));
}

// Worker persona: sbox.exe owns the lifecycle and calls into v8host.dll at the
// ACG-correct points (warmup PRE-lockdown, run POST-lockdown). This is the
// control inversion from today, where the payload owns main().
int RunWorker() {
  printf("[sbox] role=worker pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();

  SboxTarget* target = sbox_target_begin();
  if (!target) {
    printf("[sbox] worker: sbox_target_begin failed\n");
    return kBeginFailed;
  }
  const bool ping_pre = sbox_target_test_ipc(target) != 0;
  printf("[sbox] worker: IPC pre-lockdown = %s\n", ping_pre ? "OK" : "FAIL");

  // Load the payload by FULL PATH from our own app dir (PRE-lockdown: the
  // lowered token can no longer open it). Resolve the worker entrypoints.
  const std::wstring dll = sbox_harden::ExeDir() + L"v8host.dll";
  HMODULE payload = ::LoadLibraryExW(dll.c_str(), nullptr,
                                     LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                         LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
  if (!payload) {
    printf("[sbox] worker: LoadLibrary(v8host.dll) failed: %lu\n",
           ::GetLastError());
    return kDllLoadFailed;
  }
  auto warmup = reinterpret_cast<v8host_worker_warmup_fn>(
      ::GetProcAddress(payload, "v8host_worker_warmup"));
  auto run = reinterpret_cast<v8host_worker_run_fn>(
      ::GetProcAddress(payload, "v8host_worker_run"));
  auto shutdown = reinterpret_cast<v8host_worker_shutdown_fn>(
      ::GetProcAddress(payload, "v8host_worker_shutdown"));
  if (!warmup || !run || !shutdown) {
    printf("[sbox] worker: payload entrypoints missing\n");
    return kDllResolveFailed;
  }

  SboxHostServices host = {};
  host.struct_size = sizeof(host);
  host.target = target;
  host.post_message = &HostPost;
  host.inbound_event = &HostInbound;
  host.drain_messages = &HostDrain;
  host.close_event = &HostClose;

  // warmup (PRE-lockdown) -> lower_token -> run (POST-lockdown) -> shutdown.
  const int warmup_rc = warmup(&host);
  printf("[sbox] worker: v8host_worker_warmup -> %d\n", warmup_rc);
  if (warmup_rc != 0) return kWarmupFailed;

  const int lowered = sbox_target_lower_token(target);
  if (lowered != 0) {
    printf("[sbox] worker: sbox_target_lower_token failed (%d)\n", lowered);
    return kLowerTokenFailed;
  }
  printf("[sbox] worker: LowerToken survived\n");

  const bool ping_post = sbox_target_test_ipc(target) != 0;
  printf("[sbox] worker: IPC post-lockdown = %s\n", ping_post ? "OK" : "FAIL");

  const int run_rc = run(&host);
  printf("[sbox] worker: v8host_worker_run -> %d\n", run_rc);

  shutdown();
  sbox_target_end(target);

  if (!ping_pre) return kPingPreFailed;
  if (!ping_post) return kPingPostFailed;
  if (run_rc != 0) return kRunFailed;
  return kOk;
}

// --- broker ---

struct BrokerMsgCtx {
  HANDLE reply_event = nullptr;
  int replies = 0;
  bool unexpected = false;
  std::string last_reply;  // worker reply text, forwarded to the pipe client
};

void OnBrokerReply(void* ctx, int kind, const void* data, size_t len) {
  auto* c = static_cast<BrokerMsgCtx*>(ctx);
  if (kind == SBOX_MSG_STRING) {
    const std::string text(static_cast<const char*>(data), len);
    printf("[sbox] broker: worker reply = \"%s\"\n", text.c_str());
    // The worker runs real guest JS under lockdown; the built-in demo guest
    // echoes each request as "js echo: <request>" via host.postMessage.
    if (text.rfind("js echo: ", 0) == 0) {
      ++c->replies;
      c->last_reply = text;
    } else {
      c->unexpected = true;
    }
  } else {
    c->unexpected = true;
  }
  if (c->reply_event) ::SetEvent(c->reply_event);
}

// High-resolution timer for the latency measurement.
struct Perf {
  LARGE_INTEGER freq;
  Perf() { ::QueryPerformanceFrequency(&freq); }
  LONGLONG now() const {
    LARGE_INTEGER t;
    ::QueryPerformanceCounter(&t);
    return t.QuadPart;
  }
  double ms(LONGLONG a, LONGLONG b) const {
    return static_cast<double>(b - a) * 1000.0 / freq.QuadPart;
  }
};

// One timed request->reply cycle against the running worker. Returns ms, or <0.
double RoundTrip(SboxSession* session, BrokerMsgCtx* mctx, const Perf& perf,
                 const char* msg, size_t len) {
  ::ResetEvent(mctx->reply_event);
  mctx->replies = 0;
  const LONGLONG t0 = perf.now();
  if (sbox_broker_post_message(session, SBOX_MSG_STRING, msg, len) != 0)
    return -1.0;
  if (::WaitForSingleObject(mctx->reply_event, 15000) != WAIT_OBJECT_0 ||
      mctx->replies == 0)
    return -1.0;
  return perf.ms(t0, perf.now());
}

int RunBroker() {
  printf("[sbox] role=broker pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();

  const std::wstring self = SelfPath();
  if (!VerifyPayloadChain()) {
    printf("[sbox] broker: payload signature verification failed\n");
    return 3;
  }

  SboxPolicy policy = {};
  policy.struct_size = sizeof(policy);
  policy.initial_token = SBOX_TOKEN_RESTRICTED_SAME_ACCESS;
  policy.lockdown_token = SBOX_TOKEN_LOCKDOWN;
  policy.integrity = SBOX_INTEGRITY_LOW;
  policy.delayed_integrity = SBOX_INTEGRITY_UNTRUSTED;
  policy.prohibit_dynamic_code = 1;  // arm ACG so the worker probe is meaningful

  BrokerMsgCtx mctx;
  mctx.reply_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);

  // Time the one-time spawn (process creation + sandbox lockdown setup to
  // resume). Spawns THIS image with --worker (appended inside sbox_dll.cc).
  Perf perf;
  const LONGLONG t_spawn0 = perf.now();
  SboxSession* session = sbox_broker_spawn(self.c_str(), &policy, &OnBrokerReply,
                                           &mctx);
  const LONGLONG t_spawn1 = perf.now();
  if (!session) {
    printf("[sbox] broker: spawn failed\n");
    ::CloseHandle(mctx.reply_event);
    return 2;
  }

  const char msg[] = "ping from broker";
  // First (cold) round-trip also covers the worker's warmup + LowerToken +
  // reaching its run loop; the warm ones are steady-state broker<->worker RTT.
  const double first_rtt = RoundTrip(session, &mctx, perf, msg, sizeof(msg) - 1);
  const bool got_reply = first_rtt >= 0 && !mctx.unexpected;
  double warm_sum = 0;
  double warm_min = 0;
  int warm_n = 0;
  bool warm_ok = got_reply;
  for (int i = 0; i < 20 && warm_ok; ++i) {
    const double rtt = RoundTrip(session, &mctx, perf, msg, sizeof(msg) - 1);
    if (rtt < 0 || mctx.unexpected) {
      warm_ok = false;
      break;
    }
    warm_sum += rtt;
    if (warm_n == 0 || rtt < warm_min) warm_min = rtt;
    ++warm_n;
  }

  const int rc_close = sbox_broker_close(session);
  const int worker_exit = sbox_broker_wait(session);
  ::CloseHandle(mctx.reply_event);

  const double spawn_ms = perf.ms(t_spawn0, t_spawn1);
  const double warm_avg = warm_n ? warm_sum / warm_n : -1.0;
  printf("[sbox] spawn+lockdown=%.2f ms  first-roundtrip(cold)=%.3f ms"
         "  warm-roundtrip avg=%.3f min=%.3f ms (n=%d)\n",
         spawn_ms, first_rtt, warm_avg, warm_min, warm_n);

  const bool ok = got_reply && warm_ok && !mctx.unexpected && rc_close == 0 &&
                  worker_exit == kOk;
  printf("[sbox] broker: worker_exit=%d warm_rtts=%d -> %s\n", worker_exit,
         warm_n, ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}

// Named-pipe round-trip latency — models the new app->broker hop (the transport
// that used to be in-process on x64). Single process: a server thread echoes;
// the main thread times N round-trips. Isolates the pipe transport cost
// (cross-process scheduling is already in the warm broker<->worker number). No
// protocol, no auth — just RTT.
DWORD WINAPI PipeServerThread(void* arg) {
  const wchar_t* name = static_cast<const wchar_t*>(arg);
  HANDLE pipe = ::CreateNamedPipeW(
      name, PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 4096, 4096, 0,
      nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return 1;
  if (!::ConnectNamedPipe(pipe, nullptr) &&
      ::GetLastError() != ERROR_PIPE_CONNECTED) {
    ::CloseHandle(pipe);
    return 2;
  }
  char buf[256];
  DWORD n = 0;
  while (::ReadFile(pipe, buf, sizeof(buf), &n, nullptr) && n > 0) {
    DWORD wrote = 0;
    if (!::WriteFile(pipe, buf, n, &wrote, nullptr)) break;
    if (n == 4 && std::memcmp(buf, "quit", 4) == 0) break;
  }
  ::FlushFileBuffers(pipe);
  ::DisconnectNamedPipe(pipe);
  ::CloseHandle(pipe);
  return 0;
}

int RunPipeBench() {
  printf("[sbox] role=pipe-bench pid=%lu\n", ::GetCurrentProcessId());
  const wchar_t* name = L"\\\\.\\pipe\\sbox_bench";
  HANDLE th = ::CreateThread(nullptr, 0, &PipeServerThread,
                             const_cast<wchar_t*>(name), 0, nullptr);
  if (!th) return 2;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  for (int i = 0; i < 200 && pipe == INVALID_HANDLE_VALUE; ++i) {
    pipe = ::CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) ::Sleep(1);
  }
  if (pipe == INVALID_HANDLE_VALUE) {
    ::WaitForSingleObject(th, 2000);
    ::CloseHandle(th);
    return 3;
  }
  DWORD mode = PIPE_READMODE_MESSAGE;
  ::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

  Perf perf;
  const char msg[] = "ping";
  char buf[256];
  DWORD w = 0, r = 0;
  ::WriteFile(pipe, msg, sizeof(msg) - 1, &w, nullptr);  // warm the pipe once
  ::ReadFile(pipe, buf, sizeof(buf), &r, nullptr);
  double sum = 0, mn = 0;
  int n = 0;
  for (int i = 0; i < 1000; ++i) {
    const LONGLONG t0 = perf.now();
    if (!::WriteFile(pipe, msg, sizeof(msg) - 1, &w, nullptr)) break;
    if (!::ReadFile(pipe, buf, sizeof(buf), &r, nullptr)) break;
    const double rtt = perf.ms(t0, perf.now());
    sum += rtt;
    if (n == 0 || rtt < mn) mn = rtt;
    ++n;
  }
  ::WriteFile(pipe, "quit", 4, &w, nullptr);
  ::ReadFile(pipe, buf, sizeof(buf), &r, nullptr);
  ::CloseHandle(pipe);
  ::WaitForSingleObject(th, 2000);
  ::CloseHandle(th);
  printf("[sbox] named-pipe RTT avg=%.4f min=%.4f ms (n=%d)\n",
         n ? sum / n : -1.0, mn, n);
  return n > 0 ? 0 : 1;
}

// ===== shared-broker rendezvous, fan-in, per-tenant worker, lifetime =====

// Worker policy (same tier as the single-shot broker above).
SboxPolicy MakeWorkerPolicy() {
  SboxPolicy policy = {};
  policy.struct_size = sizeof(policy);
  policy.initial_token = SBOX_TOKEN_RESTRICTED_SAME_ACCESS;
  policy.lockdown_token = SBOX_TOKEN_LOCKDOWN;
  policy.integrity = SBOX_INTEGRITY_LOW;
  policy.delayed_integrity = SBOX_INTEGRITY_UNTRUSTED;
  policy.prohibit_dynamic_code = 1;
  return policy;
}

// Per-user rendezvous point: a well-known, user-scoped pipe name.
std::wstring BrokerPipeName() {
  wchar_t user[256] = {};
  DWORD n = 256;
  const std::wstring u = ::GetUserNameW(user, &n) ? user : L"default";
  return L"\\\\.\\pipe\\sbox_broker_" + u;
}

std::atomic<int> g_active_clients{0};

// One connected client: read its request, spawn a DEDICATED sandbox worker, relay
// one round-trip, and reply with the broker + worker PIDs so the client can prove
// rendezvous fan-in (same broker) and per-tenant isolation (distinct workers).
struct ClientJob {
  HANDLE pipe;
  std::wstring self;
};

DWORD WINAPI HandleClientThread(void* arg) {
  std::unique_ptr<ClientJob> job(static_cast<ClientJob*>(arg));
  HANDLE pipe = job->pipe;

  char req[256] = {};
  DWORD got = 0;
  std::string reply;
  if (::ReadFile(pipe, req, sizeof(req) - 1, &got, nullptr) && got > 0) {
    SboxPolicy policy = MakeWorkerPolicy();
    BrokerMsgCtx mctx;
    mctx.reply_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SboxSession* session = sbox_broker_spawn(job->self.c_str(), &policy,
                                             &OnBrokerReply, &mctx);
    if (session) {
      sbox_broker_post_message(session, SBOX_MSG_STRING, req, got);
      ::WaitForSingleObject(mctx.reply_event, 15000);
      sbox_broker_close(session);
      sbox_broker_wait(session);
      reply = "broker[pid=" + std::to_string(::GetCurrentProcessId()) + "] -> " +
              (mctx.last_reply.empty() ? std::string("(no worker reply)")
                                       : mctx.last_reply);
    } else {
      reply = "broker[pid=" + std::to_string(::GetCurrentProcessId()) +
              "] -> spawn FAILED";
    }
    ::CloseHandle(mctx.reply_event);
  } else {
    reply = "broker: empty request";
  }

  DWORD wrote = 0;
  ::WriteFile(pipe, reply.data(), static_cast<DWORD>(reply.size()), &wrote,
              nullptr);
  ::FlushFileBuffers(pipe);
  ::DisconnectNamedPipe(pipe);
  ::CloseHandle(pipe);
  g_active_clients.fetch_sub(1);
  return 0;
}

// Long-lived broker: ONE per user. Race-free create-or-lose via
// FILE_FLAG_FIRST_PIPE_INSTANCE; serves many clients concurrently; idle-exits.
int RunBrokerService() {
  printf("[sbox] role=broker-service pid=%lu\n", ::GetCurrentProcessId());
  sbox_harden::HardenDllSearch();
  if (!VerifyPayloadChain()) {
    printf("[sbox] broker-service: payload signature verification failed\n");
    return 2;
  }
  const std::wstring self = SelfPath();
  const std::wstring name = BrokerPipeName();

  const DWORD kIdleMs = 3000;      // idle shutdown once no clients remain
  const DWORD kMaxLifeMs = 60000;  // hard safety cap
  const DWORD t_start = ::GetTickCount();
  bool first = true;
  int served = 0;

  for (;;) {
    HANDLE pipe = ::CreateNamedPipeW(
        name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
            (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
            PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      const DWORD e = ::GetLastError();
      if (first && e == ERROR_ACCESS_DENIED) {
        printf("[sbox] broker-service: pipe already owned -> lost race, "
               "exit 0\n");
        return 0;  // another broker won the rendezvous
      }
      printf("[sbox] broker-service: CreateNamedPipe failed: %lu\n", e);
      return 2;
    }
    if (first) {
      printf("[sbox] broker-service: WON rendezvous, listening (%ls)\n",
             name.c_str());
      first = false;
    }

    OVERLAPPED ov = {};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool have_client = false;
    if (::ConnectNamedPipe(pipe, &ov)) {
      have_client = true;
    } else {
      const DWORD e = ::GetLastError();
      if (e == ERROR_PIPE_CONNECTED) {
        have_client = true;
      } else if (e == ERROR_IO_PENDING) {
        if (::WaitForSingleObject(ov.hEvent, kIdleMs) == WAIT_OBJECT_0) {
          DWORD xfer = 0;
          have_client = ::GetOverlappedResult(pipe, &ov, &xfer, FALSE);
        } else {
          ::CancelIo(pipe);
        }
      }
    }
    ::CloseHandle(ov.hEvent);

    if (have_client) {
      ++served;
      g_active_clients.fetch_add(1);
      auto* job = new ClientJob{pipe, self};
      HANDLE th = ::CreateThread(nullptr, 0, &HandleClientThread, job, 0, nullptr);
      if (th) {
        ::CloseHandle(th);
      } else {
        g_active_clients.fetch_sub(1);
        delete job;
        ::CloseHandle(pipe);
      }
    } else {
      ::CloseHandle(pipe);  // idle instance
      if (g_active_clients.load() == 0) {
        printf("[sbox] broker-service: idle %lums, no clients -> shutdown "
               "(served=%d)\n", kIdleMs, served);
        return 0;
      }
    }
    if (::GetTickCount() - t_start > kMaxLifeMs) {
      printf("[sbox] broker-service: max lifetime -> exit (served=%d)\n",
             served);
      return 0;
    }
  }
}

// Client: connect to the per-user broker, launching one if absent (the launched
// broker then wins-or-loses the create race). One request -> one response.
int RunClient() {
  printf("[sbox] role=client pid=%lu\n", ::GetCurrentProcessId());
  const std::wstring name = BrokerPipeName();
  const std::wstring self = SelfPath();

  HANDLE pipe = INVALID_HANDLE_VALUE;
  bool launched = false;
  const DWORD deadline = ::GetTickCount() + 10000;
  for (;;) {
    pipe = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
    if (pipe != INVALID_HANDLE_VALUE) break;
    const DWORD e = ::GetLastError();
    if (e == ERROR_PIPE_BUSY) {
      ::WaitNamedPipeW(name.c_str(), 2000);
    } else if (e == ERROR_FILE_NOT_FOUND) {
      if (!launched) {
        std::wstring cmd = L"\"" + self + L"\" --broker-service";
        STARTUPINFOW si = {sizeof(si)};
        PROCESS_INFORMATION pi = {};
        if (::CreateProcessW(self.c_str(), &cmd[0], nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
          ::CloseHandle(pi.hProcess);
          ::CloseHandle(pi.hThread);
        }
        launched = true;
      }
      ::Sleep(50);
    } else {
      printf("[sbox] client %lu: connect failed: %lu\n",
             ::GetCurrentProcessId(), e);
      return 2;
    }
    if (::GetTickCount() > deadline) {
      printf("[sbox] client %lu: broker unavailable\n",
             ::GetCurrentProcessId());
      return 2;
    }
  }

  DWORD mode = PIPE_READMODE_MESSAGE;
  ::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
  const std::string req =
      "ping from client " + std::to_string(::GetCurrentProcessId());
  DWORD wrote = 0, got = 0;
  char resp[512] = {};
  ::WriteFile(pipe, req.data(), static_cast<DWORD>(req.size()), &wrote, nullptr);
  const bool ok =
      ::ReadFile(pipe, resp, sizeof(resp) - 1, &got, nullptr) && got > 0;
  ::CloseHandle(pipe);
  if (!ok) {
    printf("[sbox] client %lu: no response\n", ::GetCurrentProcessId());
    return 1;
  }
  printf("[sbox] client %lu got: %.*s\n", ::GetCurrentProcessId(),
         static_cast<int>(got), resp);
  return 0;
}

// Role dispatch. Kept deliberately dumb and FIRST so neither persona can fall
// through into the other's init.
enum class Role {
  kNone,
  kBroker,
  kWorker,
  kPipeBench,
  kBrokerService,
  kClient
};

Role ParseRole(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--worker") == 0) return Role::kWorker;
    if (std::strcmp(argv[i], "--broker") == 0) return Role::kBroker;
    if (std::strcmp(argv[i], "--pipe-bench") == 0) return Role::kPipeBench;
    if (std::strcmp(argv[i], "--broker-service") == 0)
      return Role::kBrokerService;
    if (std::strcmp(argv[i], "--client") == 0) return Role::kClient;
  }
  return Role::kNone;
}

}  // namespace

int main(int argc, char** argv) {
  setvbuf(stdout, nullptr, _IONBF, 0);
  switch (ParseRole(argc, argv)) {
    case Role::kBroker:
      return RunBroker();
    case Role::kWorker:
      return RunWorker();
    case Role::kPipeBench:
      return RunPipeBench();
    case Role::kBrokerService:
      return RunBrokerService();
    case Role::kClient:
      return RunClient();
    case Role::kNone:
    default:
      printf("Usage: sbox.exe --broker | --worker | --pipe-bench | "
             "--broker-service | --client\n");
      return 2;
  }
}
