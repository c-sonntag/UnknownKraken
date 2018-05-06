#ifndef UNKNOWNECHO_RELAY_SERVICE_STRUCT_H
#define UNKNOWNECHO_RELAY_SERVICE_STRUCT_H

#include <unknownecho/protocol/api/relay/relay_server_struct.h>
#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_id_struct.h>

typedef struct {
    ue_relay_client *client;
    ue_thread_id *read_consumer_thread, *write_consumer_thread;
    bool running;
} ue_relay_service_client;

typedef struct {
    ue_relay_server *server;
    ue_relay_service_client **clients;
    unsigned short int clients_number;
    bool running;
} ue_relay_service;

#endif
