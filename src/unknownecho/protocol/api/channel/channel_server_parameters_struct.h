#ifndef UNKNOWNECHO_CHANNEL_SERVER_PARAMETERS_STRUCT_H
#define UNKNOWNECHO_CHANNEL_SERVER_PARAMETERS_STRUCT_H

#include <unknownecho/bool.h>

typedef struct {
    char *persistent_path;
    int csr_server_port;
    int tls_server_port;
    char *keystore_password;
    int channels_number;
    char *key_password;
    void *user_context;
    bool (*initialization_begin_callback)(void *user_context);
    bool (*initialization_end_callback)(void *user_context);
    bool (*uninitialization_begin_callback)(void *user_context);
    bool (*uninitialization_end_callback)(void *user_context);
} ue_channel_server_parameters;

#endif
