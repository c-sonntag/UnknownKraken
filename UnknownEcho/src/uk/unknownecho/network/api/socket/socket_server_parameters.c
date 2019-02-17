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

#include <uk/unknownecho/network/api/socket/socket_server_parameters.h>
#include <uk/utils/ueum.h>

uk_ue_socket_server_parameters *uk_ue_socket_server_parameters_build(unsigned short int port,
    bool (*read_consumer)(uk_ue_socket_client_connection *connection),
    bool (*write_consumer)(uk_ue_socket_client_connection *connection),
    uk_crypto_tls_session *tls_session) {

    uk_ue_socket_server_parameters *parameters;

    parameters = NULL;

    uk_utils_safe_alloc(parameters, uk_ue_socket_server_parameters, 1);
    parameters->port = port;
    parameters->read_consumer = read_consumer;
    parameters->write_consumer = write_consumer;
    parameters->tls_session = tls_session;

    return parameters;
}
