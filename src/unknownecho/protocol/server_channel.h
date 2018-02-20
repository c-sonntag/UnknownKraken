#ifndef UNKNOWNECHO_SERVER_CHANNEL_H
#define UNKNOWNECHO_SERVER_CHANNEL_H

#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/model/manager/tls_keystore_manager.h>
#include <unknownecho/network/api/socket/socket_server.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/protocol/relay_point.h>

typedef enum {
    UNKNOWNECHO_SERVER_WORKING_STATE,
    UNKNOWNECHO_SERVER_FREE_STATE
} ue_server_request_processing_state;

typedef struct {
    ue_pgp_keystore_manager *pgp_ks_manager;
    ue_tls_keystore_manager *tls_ks_manager;
    ue_socket_server *server;
    ue_thread_mutex *mutex;
    ue_thread_cond *cond;
    ue_tls_method *method;
    ue_server_request_processing_state processing_state;
} ue_server_channel;

ue_server_channel *ue_server_channel_create(ue_relay_point *relay_point);

void ue_server_channel_destroy(ue_server_channel *server_channel);

void ue_server_channel_start(ue_server_channel *server_channel);

#endif
