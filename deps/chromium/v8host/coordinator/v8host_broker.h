#ifndef V8HOST_COORDINATOR_V8HOST_BROKER_H_
#define V8HOST_COORDINATOR_V8HOST_BROKER_H_

#include "sbox.h"
#include <windows.h>

inline bool V8HostBrokerFinishPendingConnect(HANDLE pipe, OVERLAPPED *pending) {
  ::CancelIoEx(pipe, pending);
  DWORD transferred = 0;
  // Completion may win the race with cancellation; preserve that connection.
  return ::GetOverlappedResult(pipe, pending, &transferred, TRUE) != FALSE;
}

sbox_status V8HostBrokerRun(sbox_broker broker,
                            const sbox_broker_api* api,
                            const sbox_broker_start* start);

#endif  // V8HOST_COORDINATOR_V8HOST_BROKER_H_
