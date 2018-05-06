#ifndef UNKNOWNECHO_RELAY_CLIENT_STRUCT_H
#define UNKNOWNECHO_RELAY_CLIENT_STRUCT_H

#include <unknownecho/network/api/communication/communication_context.h>

typedef struct {
    ue_communication_context *communication_context;
    void *connection;
} ue_relay_client;

#endif
