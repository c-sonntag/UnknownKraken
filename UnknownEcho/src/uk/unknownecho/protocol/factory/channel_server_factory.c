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

#include <uk/unknownecho/protocol/factory/channel_server_factory.h>
#include <uk/unknownecho/protocol/api/channel/channel_server_parameters.h>
#include <uk/unknownecho/protocol/api/channel/channel_server_parameters_struct.h>
#include <uk/utils/ei.h>

static bool initialization_begin_callback(void *user_context) {
    uk_utils_logger_trace("Initialization begin");
    return true;
}

static bool initialization_end_callback(void *user_context){
    uk_utils_logger_trace("Initialization end");
    return true;
}

static bool uninitialization_begin_callback(void *user_context) {
    uk_utils_logger_trace("Uninitialization begin");
    return true;
}

static bool uninitialization_end_callback(void *user_context) {
    uk_utils_logger_trace("Uninitialization end");
    return true;
}

bool uk_ue_channel_server_create_default(char *keystore_password, char *key_password) {
    uk_ue_channel_server_parameters *parameters;
    bool result;

    parameters = uk_ue_channel_server_parameters_create(keystore_password, key_password);

    uk_ue_channel_server_parameters_set_initialization_begin_callback(parameters, initialization_begin_callback);

    uk_ue_channel_server_parameters_set_initialization_end_callback(parameters, initialization_end_callback);

    uk_ue_channel_server_parameters_set_uninitialization_begin_callback(parameters, uninitialization_begin_callback);

    uk_ue_channel_server_parameters_set_uninitialization_end_callback(parameters, uninitialization_end_callback);

    result = uk_ue_channel_server_parameters_build(parameters);

    uk_ue_channel_server_parameters_destroy(parameters);

    return result;
}
