#ifndef UNKNOWNECHO_CHANNEL_SERVER_PARAMETERS_H
#define UNKNOWNECHO_CHANNEL_SERVER_PARAMETERS_H

#include <unknownecho/protocol/api/channel/channel_server_parameters_struct.h>
#include <unknownecho/bool.h>

ue_channel_server_parameters *ue_channel_server_parameters_create(char *keystore_password, char *key_password);

void ue_channel_server_parameters_destroy(ue_channel_server_parameters *parameters);

bool ue_channel_server_parameters_set_persistent_path(ue_channel_server_parameters *parameters, char *persistent_path);

bool ue_channel_server_parameters_set_csr_port(ue_channel_server_parameters *parameters, int port);

bool ue_channel_server_parameters_set_tls_port(ue_channel_server_parameters *parameters, int port);

bool ue_channel_server_parameters_set_channels_number(ue_channel_server_parameters *parameters, int channels_number);

bool ue_channel_server_parameters_set_user_context(ue_channel_server_parameters *parameters, void *user_context);

bool ue_channel_server_parameters_set_initialization_begin_callback(ue_channel_server_parameters *parameters, bool (*initialization_begin_callback)(void *user_context));

bool ue_channel_server_parameters_set_initialization_end_callback(ue_channel_server_parameters *parameters, bool (*initialization_end_callback)(void *user_context));

bool ue_channel_server_parameters_set_uninitialization_begin_callback(ue_channel_server_parameters *parameters, bool (*uninitialization_begin_callback)(void *user_context));

bool ue_channel_server_parameters_set_uninitialization_end_callback(ue_channel_server_parameters *parameters, bool (*uninitialization_end_callback)(void *user_context));

bool ue_channel_server_parameters_set_cipher_name(ue_channel_server_parameters *parameters, const char *cipher_name);

bool ue_channel_server_parameters_set_digest_name(ue_channel_server_parameters *parameters, const char *digest_name);

bool ue_channel_server_parameters_build(ue_channel_server_parameters *parameters);

#endif
