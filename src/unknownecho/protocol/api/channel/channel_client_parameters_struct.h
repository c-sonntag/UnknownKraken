#ifndef UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_STRUCT_H
#define UNKNOWNECHO_CHANNEL_CLIENT_PARAMETERS_STRUCT_H

#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>

typedef struct {
    char *persistent_path;
    char *nickname;
    const char *csr_server_host;
    int csr_server_port;
    const char *tls_server_host;
    int tls_server_port;
    char *keystore_password;
    const char *server_certificates_path;
    void *user_context;
    bool (*write_callback)(void *user_context, ue_byte_stream *printer);
    bool (*initialization_begin_callback)(void *user_context);
	bool (*initialization_end_callback)(void *user_context);
    bool (*uninitialization_begin_callback)(void *user_context);
	bool (*uninitialization_end_callback)(void *user_context);
    bool (*connection_begin_callback)(void *user_context);
	bool (*connection_end_callback)(void *user_context);
    char *(*user_input_callback)(void *user_context);
} ue_channel_client_parameters;

#endif
