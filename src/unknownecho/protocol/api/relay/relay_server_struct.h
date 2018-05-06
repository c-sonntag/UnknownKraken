#ifndef UNKNOWNECHO_RELAY_SERVER_STRUCT_H
#define UNKNOWNECHO_RELAY_SERVER_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>
#include <unknownecho/thread/thread_id_struct.h>

typedef struct {
    ue_communication_context *communication_context;
    void *communication_server;
    ue_thread_id *server_thread;
} ue_relay_server;

#endif
