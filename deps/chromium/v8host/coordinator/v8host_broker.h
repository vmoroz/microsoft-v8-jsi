#ifndef V8HOST_COORDINATOR_V8HOST_BROKER_H_
#define V8HOST_COORDINATOR_V8HOST_BROKER_H_

#include "sbox.h"

sbox_status V8HostBrokerRun(sbox_broker broker,
                            const sbox_broker_api* api,
                            const sbox_broker_start* start);

#endif  // V8HOST_COORDINATOR_V8HOST_BROKER_H_
