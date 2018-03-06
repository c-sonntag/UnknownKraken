#ifndef UNKNOWNECHO_SOCKET_SERVER_CHANNEL_H
#define UNKNOWNECHO_SOCKET_SERVER_CHANNEL_H

#include <unknownecho/bool.h>

bool ue_socket_server_channel_create(char *persistent_path,
    unsigned short int csr_server_port, unsigned short int tls_server_port,
    char *keystore_password, int channels_number, char *server_key_password);

void ue_socket_server_channel_destroy();

bool ue_socket_server_channel_process();

#endif
