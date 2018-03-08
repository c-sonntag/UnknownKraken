#ifndef UNKNOWNECHO_CLIENT_CHANNEL_H
#define UNKNOWNECHO_CLIENT_CHANNEL_H

#include <unknownecho/bool.h>
#include <unknownecho/protocol/api/channel/client_channel_struct.h>
#include <unknownecho/byte/byte_stream.h>

bool ue_client_channel_init();

void ue_client_channel_uninit();

ue_client_channel *ue_client_channel_create(char *root_path, char *nickname, const char *csr_server_host, int csr_server_port,
	const char *tls_server_host, int tls_server_port, char *keystore_password, bool (*write_consumer)(ue_byte_stream *printer));

void ue_client_channel_destroy(ue_client_channel *client_channel);

bool ue_client_channel_start(ue_client_channel *client_channel);

#endif
