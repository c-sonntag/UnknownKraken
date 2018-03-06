#ifndef UNKNOWNECHO_SOCKET_CLIENT_CHANNEL_H
#define UNKNOWNECHO_SOCKET_CLIENT_CHANNEL_H

#include <unknownecho/bool.h>

bool ue_socket_client_channel_create(char *root_path, char *nickname, const char *csr_server_host, int csr_server_port,
	const char *tls_server_host, int tls_server_port, char *keystore_password);

void ue_socket_client_channel_destroy();

bool ue_socket_client_channel_start();

#endif
