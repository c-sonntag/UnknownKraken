/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <unknownecho/protocol/api/channel/channel_client_parameters.h>
#include <unknownecho/protocol/api/channel/channel_client.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <unknownecho/defines.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

ue_channel_client_parameters *ue_channel_client_parameters_create(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer)) {
    ue_channel_client_parameters *parameters;

    ei_check_parameter_or_return(nickname);
    ei_check_parameter_or_return(keystore_password);

    parameters = NULL;

    ueum_safe_alloc(parameters, ue_channel_client_parameters, 1);
    parameters->persistent_path = NULL;
    parameters->nickname = ueum_string_create_from(nickname);
    parameters->csr_server_host = NULL;
    parameters->csr_server_port = -1;
    parameters->csl_server_host = NULL;
    parameters->csl_server_port = -1;
    parameters->keystore_password = ueum_string_create_from(keystore_password);
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
    parameters->cipher_name = NULL;
    parameters->digest_name = NULL;
    parameters->user_input_mode = UNKNOWNECHOUTILSMODULE_STDIN_INPUT;

    return parameters;
}

void ue_channel_client_parameters_destroy(ue_channel_client_parameters *parameters) {
    if (parameters) {
        ueum_safe_free(parameters->persistent_path);
        ueum_safe_free(parameters->nickname);
        ueum_safe_free(parameters->csr_server_host);
        ueum_safe_free(parameters->csl_server_host);
        ueum_safe_free(parameters->keystore_password);
        ueum_safe_free(parameters->server_certificates_path);
        ueum_safe_free(parameters->cipher_name);
        ueum_safe_free(parameters->digest_name);
        ueum_safe_free(parameters);
    }
}

bool ue_channel_client_parameters_set_persistent_path(ue_channel_client_parameters *parameters, char *persistent_path) {
    parameters->persistent_path = ueum_string_create_from(persistent_path);
    return true;
}

bool ue_channel_client_parameters_set_csr_host(ue_channel_client_parameters *parameters, const char *host) {
    parameters->csr_server_host = ueum_string_create_from(host);
    return true;
}

bool ue_channel_client_parameters_set_csr_port(ue_channel_client_parameters *parameters, int port) {
    parameters->csr_server_port = port;
    return true;
}

bool ue_channel_client_parameters_set_csl_host(ue_channel_client_parameters *parameters, const char *host) {
    parameters->csl_server_host = ueum_string_create_from(host);
    return true;
}

bool ue_channel_client_parameters_set_csl_port(ue_channel_client_parameters *parameters, int port) {
    parameters->csl_server_port = port;
    return true;
}

bool ue_channel_client_parameters_set_certificates_path(ue_channel_client_parameters *parameters, const char *certificates_path) {
    parameters->server_certificates_path = ueum_string_create_from(certificates_path);
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

bool ue_channel_client_parameters_set_cipher_name(ue_channel_client_parameters *parameters, const char *cipher_name) {
    parameters->cipher_name = ueum_string_create_from(cipher_name);
    return true;
}

bool ue_channel_client_parameters_set_digest_name(ue_channel_client_parameters *parameters, const char *digest_name) {
    parameters->digest_name = ueum_string_create_from(digest_name);
    return true;
}

bool ue_channel_client_parameters_set_user_input_mode(ue_channel_client_parameters *parameters, ueum_user_input_mode user_input_mode) {
    parameters->user_input_mode = user_input_mode;
    return true;
}

bool ue_channel_client_parameters_set_communication_type(ue_channel_client_parameters *parameters, ue_communication_type communication_type) {
    parameters->communication_type = communication_type;
    return true;
}

ue_channel_client *ue_channel_client_parameters_build(ue_channel_client_parameters *parameters) {
    ue_channel_client *channel_client;

    if (!parameters->persistent_path) {
        parameters->persistent_path = ueum_string_create_from(UNKNOWNECHO_DEFAULT_CLIENT_PERSISTENT_PATH);
    }

    if (!parameters->csr_server_host) {
        parameters->csr_server_host = ueum_string_create_from(UNKNOWNECHO_LOCALHOST);
    }

    if (parameters->csr_server_port == -1) {
        parameters->csr_server_port = UNKNOWNECHO_DEFAULT_CSR_SERVER_PORT;
    }

    if (!parameters->csl_server_host) {
        parameters->csl_server_host = ueum_string_create_from(UNKNOWNECHO_LOCALHOST);
    }

    if (parameters->csl_server_port == -1) {
        parameters->csl_server_port = UNKNOWNECHO_DEFAULT_CSL_SERVER_PORT;
    }

    if (!parameters->server_certificates_path) {
        parameters->server_certificates_path = ueum_string_create_from(UNKNOWNECHO_DEFAULT_SERVER_CERTIFICATES_PATH);
    }

    if (!parameters->cipher_name) {
        parameters->cipher_name = ueum_string_create_from(UNKNOWNECHO_DEFAULT_CIPHER_NAME);
    }

    if (!parameters->digest_name) {
        parameters->digest_name = ueum_string_create_from(UNKNOWNECHO_DEFAULT_DIGEST_NAME);
    }

    if (!parameters->communication_type) {
        parameters->communication_type = UNKNOWNECHO_DEFAULT_COMMUNICATION_TYPE_ID;
    }

    channel_client = ue_channel_client_create(parameters->persistent_path, parameters->nickname, parameters->csr_server_host, parameters->csr_server_port,
        parameters->csl_server_host, parameters->csl_server_port, parameters->keystore_password, parameters->server_certificates_path,
        parameters->user_context, parameters->write_callback, parameters->initialization_begin_callback, parameters->initialization_end_callback,
        parameters->uninitialization_begin_callback, parameters->uninitialization_end_callback, parameters->connection_begin_callback,
        parameters->connection_end_callback, parameters->user_input_callback, parameters->cipher_name, parameters->digest_name,
        parameters->user_input_mode, parameters->communication_type);

    return channel_client;
}