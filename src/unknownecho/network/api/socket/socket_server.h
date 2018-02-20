#ifndef UNKNOWNECHO_SOCKET_SERVER_H
#define UNKNOWNECHO_SOCKET_SERVER_H

#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/model/manager/tls_keystore_manager_struct.h>
#include <unknownecho/bool.h>

typedef struct {
	int ue_socket_fd;
	ue_socket_client_connection **connections;
	int connections_number, simultaneous_connections_number;
	bool (*read_consumer)(ue_socket_client_connection *connection);
	bool (*write_consumer)(ue_socket_client_connection *connection);
	bool running;
	ue_tls_keystore_manager *tls_ks_manager;
} ue_socket_server;

ue_socket_server *ue_socket_server_create(unsigned short int port,
	bool (*read_consumer)(ue_socket_client_connection *connection),
	bool (*write_consumer)(ue_socket_client_connection *connection),
	ue_tls_keystore_manager *keystore_manager);

bool ue_socket_server_is_valid(ue_socket_server *server);

void ue_socket_server_destroy(ue_socket_server *server);

void ue_socket_server_process_polling(ue_socket_server *server);

#endif
