#include <unknownecho/protocol/api/channel/channel_client_parameters.h>
#include <unknownecho/protocol/api/channel/channel_client.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>

#define DEFAULT_CSR_SERVER_PORT          5002
#define DEFAULT_TLS_SERVER_PORT          5001
#define DEFAULT_PERSISTENT_PATH          "out"
#define DEFAULT_SERVER_CERTIFICATES_PATH "out/certificate"
#define LOCALHOST                        "127.0.0.1"

ue_channel_client_parameters *ue_channel_client_parameters_create(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ue_byte_stream *printer)) {
    ue_channel_client_parameters *parameters;

    ue_safe_alloc(parameters, ue_channel_client_parameters, 1);
    parameters->persistent_path = NULL;
    parameters->nickname = ue_string_create_from(nickname);
    parameters->csr_server_host = NULL;
    parameters->csr_server_port = -1;
    parameters->tls_server_host = NULL;
    parameters->tls_server_port = -1;
    parameters->keystore_password = ue_string_create_from(keystore_password);
    parameters->server_certificates_path = NULL;
    parameters->user_context = NULL;
    parameters->write_callback = write_callback;
    parameters->initialization_begin_callback = NULL;
	parameters->initialization_end_callback = NULL;
    parameters->uninitialization_begin_callback = NULL;
	parameters->uninitialization_end_callback = NULL;
    parameters->connection_begin_callback = NULL;
	parameters->connection_end_callback = NULL;
    parameters->user_input_callback = NULL;

    return parameters;
}

void ue_channel_client_parameters_destroy(ue_channel_client_parameters *parameters) {
    if (parameters) {
        ue_safe_free(parameters->persistent_path);
        ue_safe_free(parameters->nickname);
        ue_safe_free(parameters->csr_server_host);
        ue_safe_free(parameters->tls_server_host);
        ue_safe_free(parameters->keystore_password);
        ue_safe_free(parameters->server_certificates_path);
        ue_safe_free(parameters);
    }
}

bool ue_channel_client_parameters_set_persistent_path(ue_channel_client_parameters *parameters, char *persistent_path) {
    parameters->persistent_path = ue_string_create_from(persistent_path);
    return true;
}

bool ue_channel_client_parameters_set_csr_host(ue_channel_client_parameters *parameters, const char *host) {
    parameters->csr_server_host = ue_string_create_from(host);
    return true;
}

bool ue_channel_client_parameters_set_csr_port(ue_channel_client_parameters *parameters, int port) {
    parameters->csr_server_port = port;
    return true;
}

bool ue_channel_client_parameters_set_tls_host(ue_channel_client_parameters *parameters, const char *host) {
    parameters->tls_server_host = ue_string_create_from(host);
    return true;
}

bool ue_channel_client_parameters_set_tls_port(ue_channel_client_parameters *parameters, int port) {
    parameters->tls_server_port = port;
    return true;
}

bool ue_channel_client_parameters_set_certificates_path(ue_channel_client_parameters *parameters, const char *certificates_path) {
    parameters->server_certificates_path = ue_string_create_from(certificates_path);
    return true;
}

bool ue_channel_client_parameters_set_user_context(ue_channel_client_parameters *parameters, void *user_context) {
    parameters->user_context = user_context;
    return true;
}

bool ue_channel_client_parameters_set_initialization_begin_callback(ue_channel_client_parameters *parameters, bool (*initialization_begin_callback)(void *user_context)) {
    parameters->initialization_begin_callback = initialization_begin_callback;
    return true;
}

bool ue_channel_client_parameters_set_initialization_end_callback(ue_channel_client_parameters *parameters, bool (*initialization_end_callback)(void *user_context)) {
    parameters->initialization_end_callback = initialization_end_callback;
    return true;
}

bool ue_channel_client_parameters_set_uninitialization_begin_callback(ue_channel_client_parameters *parameters, bool (*uninitialization_begin_callback)(void *user_context)) {
    parameters->uninitialization_begin_callback = uninitialization_begin_callback;
    return true;
}

bool ue_channel_client_parameters_set_uninitialization_end_callback(ue_channel_client_parameters *parameters, bool (*uninitialization_end_callback)(void *user_context)) {
    parameters->uninitialization_end_callback = uninitialization_end_callback;
    return true;
}

bool ue_channel_client_parameters_set_connection_begin_callback(ue_channel_client_parameters *parameters, bool (*connection_begin_callback)(void *user_context)) {
    parameters->connection_begin_callback = connection_begin_callback;
    return true;
}

bool ue_channel_client_parameters_set_connection_end_callback(ue_channel_client_parameters *parameters, bool (*connection_end_callback)(void *user_context)) {
    parameters->connection_end_callback = connection_end_callback;
    return true;
}

bool ue_channel_client_parameters_set_user_input_callback(ue_channel_client_parameters *parameters, char *(*user_input_callback)(void *user_context)) {
    parameters->user_input_callback = user_input_callback;
    return true;
}

ue_channel_client *ue_channel_client_parameters_build(ue_channel_client_parameters *parameters) {
    ue_channel_client *channel_client;

    if (!parameters->persistent_path) {
        parameters->persistent_path = ue_string_create_from(DEFAULT_PERSISTENT_PATH);
    }

    if (!parameters->csr_server_host) {
        parameters->csr_server_host = ue_string_create_from(LOCALHOST);
    }

    if (parameters->csr_server_port == -1) {
        parameters->csr_server_port = DEFAULT_CSR_SERVER_PORT;
    }

    if (!parameters->tls_server_host) {
        parameters->tls_server_host = ue_string_create_from(LOCALHOST);
    }

    if (parameters->tls_server_port == -1) {
        parameters->tls_server_port = DEFAULT_TLS_SERVER_PORT;
    }

    if (!parameters->server_certificates_path) {
        parameters->server_certificates_path = ue_string_create_from(DEFAULT_SERVER_CERTIFICATES_PATH);
    }

    channel_client = ue_channel_client_create(parameters->persistent_path, parameters->nickname, parameters->csr_server_host, parameters->csr_server_port,
    	parameters->tls_server_host, parameters->tls_server_port, parameters->keystore_password, parameters->server_certificates_path,
        parameters->user_context, parameters->write_callback, parameters->initialization_begin_callback, parameters->initialization_end_callback,
        parameters->uninitialization_begin_callback, parameters->uninitialization_end_callback, parameters->connection_begin_callback,
    	parameters->connection_end_callback, parameters->user_input_callback);

    return channel_client;
}
