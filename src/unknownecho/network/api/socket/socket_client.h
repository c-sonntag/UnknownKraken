#ifndef UNKNOWNECHO_SOCKET_CLIENT_H
#define UNKNOWNECHO_SOCKET_CLIENT_H

#include <unknownecho/network/api/socket/socket_client_connection.h>
#include <unknownecho/network/api/tls/tls_keystore.h>

ue_socket_client_connection *ue_socket_connect(int fd, int domain, const char *host, unsigned short int port, ue_tls_keystore *keystore);

ue_socket_client_connection *ue_socket_connect_s(int fd, const char *domain, const char *host, const char *port, ue_tls_keystore *keystore);

#endif
