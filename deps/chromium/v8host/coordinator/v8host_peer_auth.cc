#include "v8host_peer_auth.h"

namespace v8host {
namespace {

bool SameCreationInstance(HANDLE expected, const HeldProcess& actual) {
  if (!expected)
    return true;
  if (::GetProcessId(expected) != actual.pid())
    return false;
  FILETIME creation = {}, exit = {}, kernel = {}, user = {};
  return ::GetProcessTimes(expected, &creation, &exit, &kernel, &user) &&
         creation.dwLowDateTime == actual.creation_time().dwLowDateTime &&
         creation.dwHighDateTime == actual.creation_time().dwHighDateTime;
}

bool ReadPeerPid(HANDLE pipe, PeerSide side, DWORD* pid) {
  ULONG value = 0;
  const BOOL ok =
      side == PeerSide::kPipeClient
          ? ::GetNamedPipeClientProcessId(pipe, &value)
          : ::GetNamedPipeServerProcessId(pipe, &value);
  if (ok)
    *pid = value;
  return ok != FALSE;
}

}  // namespace

bool AuthenticatePipePeer(HANDLE pipe,
                          const PeerAuthPolicy& policy,
                          HeldProcess* peer,
                          DWORD* error,
                          const PeerAuthHooks* hooks) {
  using ReadPidFn = std::function<bool(HANDLE, PeerSide, DWORD*)>;
  using QueryFn = std::function<bool(DWORD, HeldProcess*, DWORD*)>;
  using SameInstFn = std::function<bool(HANDLE, const HeldProcess&)>;
  const ReadPidFn read_pid = hooks && hooks->read_peer_pid
                                 ? hooks->read_peer_pid
                                 : ReadPidFn(ReadPeerPid);
  const QueryFn query = hooks && hooks->query_identity
                            ? hooks->query_identity
                            : QueryFn(QueryProcessIdentity);
  const SameInstFn same_inst = hooks && hooks->same_creation_instance
                                   ? hooks->same_creation_instance
                                   : SameInstFn(SameCreationInstance);
  DWORD first_pid = 0;
  HeldProcess identity;
  DWORD second_pid = 0;
  if (pipe == INVALID_HANDLE_VALUE || !peer)
    goto fail;
  if (!read_pid(pipe, policy.peer_side, &first_pid))
    goto fail;
  if (!query(first_pid, &identity, error))
    goto fail;
  if (identity.pid() != first_pid ||
      !read_pid(pipe, policy.peer_side, &second_pid) ||
      second_pid != first_pid)
    goto fail;
  if (!EqualSidBytes(identity.sid(), policy.expected_sid) ||
      !EqualLuid(identity.logon_session(), policy.expected_session))
    goto fail;
  if (!TrustAllowed(VerifyTrust(identity.image())))
    goto fail;
  if (policy.expected_image &&
      !IsSameFileIdentity(identity.image(), *policy.expected_image))
    goto fail;
  if (policy.mode == BrokerMode::kShared &&
      !IsStrictDescendant(policy.install_root, identity.image().final_path()))
    goto fail;
  if (!same_inst(policy.launched_process, identity) ||
      !read_pid(pipe, policy.peer_side, &second_pid) ||
      second_pid != first_pid)
    goto fail;
  {
    *peer = std::move(identity);
    if (error)
      *error = ERROR_SUCCESS;
    return true;
  }
fail:
  {
    if (error && *error == ERROR_SUCCESS)
      *error = ERROR_ACCESS_DENIED;
    return false;
  }
}

}  // namespace v8host
