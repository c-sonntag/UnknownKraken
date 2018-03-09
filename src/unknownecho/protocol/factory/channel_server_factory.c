/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/protocol/factory/channel_server_factory.h>
#include <unknownecho/protocol/api/channel/channel_server_parameters.h>
#include <unknownecho/protocol/api/channel/channel_server_parameters_struct.h>
#include <unknownecho/errorHandling/logger.h>

static bool initialization_begin_callback(void *user_context) {
    ue_logger_trace("Initialization begin");
    return true;
}

static bool initialization_end_callback(void *user_context){
    ue_logger_trace("Initialization end");
    return true;
}

static bool uninitialization_begin_callback(void *user_context) {
    ue_logger_trace("Uninitialization begin");
    return true;
}

static bool uninitialization_end_callback(void *user_context) {
    ue_logger_trace("Uninitialization end");
    return true;
}

bool ue_channel_server_create_default(char *keystore_password, char *key_password) {
    ue_channel_server_parameters *parameters;
    bool result;

    parameters = ue_channel_server_parameters_create(keystore_password, key_password);

    ue_channel_server_parameters_set_initialization_begin_callback(parameters, initialization_begin_callback);

    ue_channel_server_parameters_set_initialization_end_callback(parameters, initialization_end_callback);

    ue_channel_server_parameters_set_uninitialization_begin_callback(parameters, uninitialization_begin_callback);

    ue_channel_server_parameters_set_uninitialization_end_callback(parameters, uninitialization_end_callback);

    result = ue_channel_server_parameters_build(parameters);

    ue_channel_server_parameters_destroy(parameters);

    return result;
}
