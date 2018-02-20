#ifndef UNKNOWNECHO_CLIENT_CHANNEL
#define UNKNOWNECHO_CLIENT_CHANNEL

#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/model/manager/tls_keystore_manager.h>
#include <unknownecho/model/message/plain_message.h>
#include <unknownecho/model/message/cipher_message.h>
#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>

typedef enum {
	UNKNOWNECHO_CLIENT_READING_STATE,
	UNKNOWNECHO_CLIENT_WRITING_STATE,
	UNKNOWNECHO_CLIENT_CLOSING_STATE
} ue_client_data_transmission_state;

typedef struct {
    ue_pgp_keystore_manager *pgp_ks_manager;
	ue_tls_keystore_manager *tls_ks_manager;
	ue_socket_client_connection *connection;
	ue_thread_id *read_thread, *write_thread;
	ue_thread_mutex *mutex;
	ue_thread_cond *cond;
	ue_client_data_transmission_state transmission_state;
    ue_tls_method *method;
	bool running;
    /* Only one identifier through the network (to change ?) */
    char *nickname;
	ue_string_builder *new_message;
	ue_plain_message *pmsg;
	ue_cipher_message *cmsg;
	bool communicating;
} ue_client_channel;

ue_client_channel *ue_client_channel_create(ue_relay_point *relay_point);

void ue_client_channel_destroy(ue_client_channel *client_channel);

bool ue_client_channel_start(ue_client_channel *client_channel);

void ue_client_channel_wait(ue_client_channel *client_channel);

#endif
