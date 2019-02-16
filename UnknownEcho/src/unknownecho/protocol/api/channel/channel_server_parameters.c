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

#include <unknownecho/protocol/api/channel/channel_server_parameters.h>
#include <unknownecho/protocol/api/channel/channel_server.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <unknownecho/defines.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

ue_channel_server_parameters *ue_channel_server_parameters_create(char *keystore_password, char *key_password) {
    ue_channel_server_parameters *parameters;

    ei_check_parameter_or_return(keystore_password);

    parameters = NULL;

    ueum_safe_alloc(parameters, ue_channel_server_parameters, 1);
    parameters->persistent_path = NULL;
    parameters->csr_server_port = -1;
    parameters->csl_server_port = -1;
    parameters->keystore_password = ueum_string_create_from(keystore_password);
    parameters->channels_number = -1;
    if (key_password) {
        parameters->key_password = ueum_string_create_from(key_password);
    } else {
        parameters->key_password = NULL;
    }
    parameters->user_context = NULL;
    parameters->initialization_begin_callback = NULL;
    parameters->initialization_end_callback = NULL;
    parameters->uninitialization_begin_callback = NULL;
    parameters->uninitialization_end_callback = NULL;
    parameters->cipher_name = NULL;
    parameters->digest_name = NULL;

    return parameters;
}

void ue_channel_server_parameters_destroy(ue_channel_server_parameters *parameters) {
    if (parameters) {
        ueum_safe_free(parameters->persistent_path);
        ueum_safe_free(parameters->keystore_password);
        ueum_safe_free(parameters->key_password);
        ueum_safe_free(parameters->cipher_name);
        ueum_safe_free(parameters->digest_name);
        ueum_safe_free(parameters);
    }
}

bool ue_channel_server_parameters_set_persistent_path(ue_channel_server_parameters *parameters, char *persistent_path) {
    parameters->persistent_path = ueum_string_create_from(persistent_path);
    return true;
}

bool ue_channel_server_parameters_set_csr_port(ue_channel_server_parameters *parameters, int port) {
    parameters->csr_server_port = port;
    return true;
}

bool ue_channel_server_parameters_set_tls_port(ue_channel_server_parameters *parameters, int port) {
    parameters->csl_server_port = port;
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

bool ue_channel_server_parameters_set_cipher_name(ue_channel_server_parameters *parameters, const char *cipher_name) {
    parameters->cipher_name = ueum_string_create_from(cipher_name);
    return true;
}

bool ue_channel_server_parameters_set_digest_name(ue_channel_server_parameters *parameters, const char *digest_name) {
    parameters->digest_name = ueum_string_create_from(digest_name);
    return true;
}

bool ue_channel_server_parameters_set_communication_type(ue_channel_server_parameters *parameters, ue_communication_type communication_type) {
    parameters->communication_type = communication_type;
    return true;
}

bool ue_channel_server_parameters_build(ue_channel_server_parameters *parameters) {
    if (!parameters->persistent_path) {
        parameters->persistent_path = ueum_string_create_from(UNKNOWNECHO_DEFAULT_SERVER_PERSISTENT_PATH);
    }

    if (parameters->csr_server_port == -1) {
        parameters->csr_server_port = UNKNOWNECHO_DEFAULT_CSR_SERVER_PORT;
    }

    if (parameters->csl_server_port == -1) {
        parameters->csl_server_port = UNKNOWNECHO_DEFAULT_CSL_SERVER_PORT;
    }

    if (parameters->channels_number == -1) {
        parameters->channels_number = UNKNOWNECHO_DEFAULT_CLIENT_CHANNELS_NUMBER;
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

    return ue_channel_server_create(parameters->persistent_path, parameters->csr_server_port,
        parameters->csl_server_port, parameters->keystore_password, parameters->channels_number,
        parameters->key_password, parameters->user_context, parameters->initialization_begin_callback,
        parameters->initialization_end_callback, parameters->uninitialization_begin_callback,
        parameters->uninitialization_end_callback, parameters->cipher_name, parameters->digest_name,
        parameters->communication_type);
}