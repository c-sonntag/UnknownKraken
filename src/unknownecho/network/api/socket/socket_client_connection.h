#ifndef UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H
#define UNKNOWNECHO_SOCKET_CLIENT_UNKNOWNECHO_CONNECTION_H

#include <unknownecho/bool.h>
#include <unknownecho/string/string_builder.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/container/string_vector.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/network/api/tls/tls_connection.h>

typedef enum {
	UNKNOWNECHO_CONNECTION_FREE_STATE,
	UNKNOWNECHO_CONNECTION_READ_STATE,
	UNKNOWNECHO_CONNECTION_WRITE_STATE
} ue_connection_state;

typedef struct {
	int fd;
	ue_string_builder *received_message, *message_to_send;
	ue_connection_state state;
	char *nickname;
	ue_string_vector *split_message, *all_messages, *tmp_message, *current_message;
	ue_tls_connection *tls;
	ue_x509_certificate *peer_certificate;
	ue_byte_stream *received_message_stream;
	bool established;
	void *optional_data;
} ue_socket_client_connection;

ue_socket_client_connection *ue_socket_client_connection_init();

void ue_socket_client_connection_destroy(ue_socket_client_connection *connection);

void ue_socket_client_connection_clean_up(ue_socket_client_connection *connection);

bool ue_socket_client_connection_is_available(ue_socket_client_connection *connection);

bool ue_socket_client_connection_establish(ue_socket_client_connection *connection, int ue_socket_fd);

bool ue_socket_client_connection_is_established(ue_socket_client_connection *connection);

#endif
