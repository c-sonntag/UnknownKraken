#include <unknownecho/protocol/api/channel/channel_server_parameters.h>
#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>

#define DEFAULT_PERSISTENT_PATH "out/server"
#define DEFAULT_CSR_SERVER_PORT 5002
#define DEFAULT_TLS_SERVER_PORT 5001
#define DEFAULT_CHANNELS_NUMBER 3

ue_channel_server_parameters *ue_channel_server_parameters_create(char *keystore_password, char *key_password) {
    ue_channel_server_parameters *parameters;

    ue_safe_alloc(parameters, ue_channel_server_parameters, 1);
    parameters->persistent_path = NULL;
    parameters->csr_server_port = -1;
    parameters->tls_server_port = -1;
    parameters->keystore_password = ue_string_create_from(keystore_password);
    parameters->channels_number = -1;
    parameters->key_password = ue_string_create_from(key_password);
    parameters->user_context = NULL;
    parameters->initialization_begin_callback = NULL;
    parameters->initialization_end_callback = NULL;
    parameters->uninitialization_begin_callback = NULL;
    parameters->uninitialization_end_callback = NULL;

    return parameters;
}

void ue_channel_server_parameters_destroy(ue_channel_server_parameters *parameters) {
    if (parameters) {
        ue_safe_free(parameters->persistent_path);
        ue_safe_free(parameters->keystore_password);
        ue_safe_free(parameters->key_password);
        ue_safe_free(parameters);
    }
}

bool ue_channel_server_parameters_set_persistent_path(ue_channel_server_parameters *parameters, char *persistent_path) {
    parameters->persistent_path = ue_string_create_from(persistent_path);
    return true;
}

bool ue_channel_server_parameters_set_csr_port(ue_channel_server_parameters *parameters, int port) {
    parameters->csr_server_port = port;
    return true;
}

bool ue_channel_server_parameters_set_tls_port(ue_channel_server_parameters *parameters, int port) {
    parameters->tls_server_port = port;
    return true;
}

bool ue_channel_server_parameters_set_channels_number(ue_channel_server_parameters *parameters, int channels_number) {
    parameters->channels_number = channels_number;
    return true;
}

bool ue_channel_server_parameters_set_user_context(ue_channel_server_parameters *parameters, void *user_context) {
    parameters->user_context = user_context;
    return true;
}

bool ue_channel_server_parameters_set_initialization_begin_callback(ue_channel_server_parameters *parameters, bool (*initialization_begin_callback)(void *user_context)) {
    parameters->initialization_begin_callback = initialization_begin_callback;
    return true;
}

bool ue_channel_server_parameters_set_initialization_end_callback(ue_channel_server_parameters *parameters, bool (*initialization_end_callback)(void *user_context)) {
    parameters->initialization_end_callback = initialization_end_callback;
    return true;
}

bool ue_channel_server_parameters_set_uninitialization_begin_callback(ue_channel_server_parameters *parameters, bool (*uninitialization_begin_callback)(void *user_context)) {
    parameters->uninitialization_begin_callback = uninitialization_begin_callback;
    return true;
}

bool ue_channel_server_parameters_set_uninitialization_end_callback(ue_channel_server_parameters *parameters, bool (*uninitialization_end_callback)(void *user_context)) {
    parameters->uninitialization_end_callback = uninitialization_end_callback;
    return true;
}

bool ue_channel_server_parameters_build(ue_channel_server_parameters *parameters) {
    if (!parameters->persistent_path) {
        parameters->persistent_path = ue_string_create_from(DEFAULT_PERSISTENT_PATH);
    }

    if (parameters->csr_server_port == -1) {
        parameters->csr_server_port = DEFAULT_CSR_SERVER_PORT;
    }

    if (parameters->tls_server_port == -1) {
        parameters->tls_server_port = DEFAULT_TLS_SERVER_PORT;
    }

    if (parameters->channels_number == -1) {
        parameters->channels_number = DEFAULT_CHANNELS_NUMBER;
    }

    return ue_channel_server_create(parameters->persistent_path, parameters->csr_server_port,
        parameters->tls_server_port, parameters->keystore_password, parameters->channels_number,
        parameters->key_password, parameters->user_context, parameters->initialization_begin_callback,
        parameters->initialization_end_callback, parameters->uninitialization_begin_callback,
        parameters->uninitialization_end_callback);
}
