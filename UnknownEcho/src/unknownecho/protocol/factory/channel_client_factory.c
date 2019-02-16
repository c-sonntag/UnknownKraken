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

#include <unknownecho/protocol/factory/channel_client_factory.h>
#include <unknownecho/protocol/api/channel/channel_client_parameters.h>
#include <unknownecho/protocol/api/channel/channel_client_parameters_struct.h>
#include <ei/ei.h>

static bool initialization_begin_callback(void *user_context) {
    ei_logger_trace("Initialization begin");
    return true;
}

static bool initialization_end_callback(void *user_context){
    ei_logger_trace("Initialization end");
    return true;
}

static bool uninitialization_begin_callback(void *user_context) {
    ei_logger_trace("Uninitialization begin");
    return true;
}

static bool uninitialization_end_callback(void *user_context) {
    ei_logger_trace("Uninitialization end");
    return true;
}

static bool connection_begin_callback(void *user_context) {
    ei_logger_trace("Connection begin");
    return true;
}

static bool connection_end_callback(void *user_context) {
    ei_logger_trace("Connection end");
    return true;
}

ue_channel_client *ue_channel_client_create_default_local(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer)) {
    ue_channel_client_parameters *parameters;
    ue_channel_client *channel_client;

    parameters = ue_channel_client_parameters_create(nickname, keystore_password, write_callback);

    ue_channel_client_parameters_set_initialization_begin_callback(parameters, initialization_begin_callback);

    ue_channel_client_parameters_set_initialization_end_callback(parameters, initialization_end_callback);

    ue_channel_client_parameters_set_uninitialization_begin_callback(parameters, uninitialization_begin_callback);

    ue_channel_client_parameters_set_uninitialization_end_callback(parameters, uninitialization_end_callback);

    ue_channel_client_parameters_set_connection_begin_callback(parameters, connection_begin_callback);

    ue_channel_client_parameters_set_connection_end_callback(parameters, connection_end_callback);

    channel_client = ue_channel_client_parameters_build(parameters);

    ue_channel_client_parameters_destroy(parameters);

    return channel_client;
}

ue_channel_client *ue_channel_client_create_default_remote(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ueum_byte_stream *printer),
    const char *host) {
    ue_channel_client_parameters *parameters;
    ue_channel_client *channel_client;

    parameters = ue_channel_client_parameters_create(nickname, keystore_password, write_callback);

    ue_channel_client_parameters_set_csl_host(parameters, host);

    ue_channel_client_parameters_set_csr_host(parameters, host);

    ue_channel_client_parameters_set_initialization_begin_callback(parameters, initialization_begin_callback);

    ue_channel_client_parameters_set_initialization_end_callback(parameters, initialization_end_callback);

    ue_channel_client_parameters_set_uninitialization_begin_callback(parameters, uninitialization_begin_callback);

    ue_channel_client_parameters_set_uninitialization_end_callback(parameters, uninitialization_end_callback);

    ue_channel_client_parameters_set_connection_begin_callback(parameters, connection_begin_callback);

    ue_channel_client_parameters_set_connection_end_callback(parameters, connection_end_callback);

    channel_client = ue_channel_client_parameters_build(parameters);

    ue_channel_client_parameters_destroy(parameters);

    return channel_client;
}
