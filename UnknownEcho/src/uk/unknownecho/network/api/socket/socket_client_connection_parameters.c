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

#include <uk/unknownecho/network/api/socket/socket_client_connection_parameters.h>
#include <uk/utils/ueum.h>

uk_ue_socket_client_connection_parameters *uk_ue_socket_client_connection_parameters_build(int fd, int domain,
    const char *host, unsigned short int port, uk_crypto_tls_session *tls_session) {

    uk_ue_socket_client_connection_parameters *parameters;

    parameters = NULL;

    uk_utils_safe_alloc(parameters, uk_ue_socket_client_connection_parameters, 1);
    parameters->fd = fd;
    parameters->domain = domain;
    parameters->domain_s = NULL;
    parameters->host = host;
    parameters->port = port;
    parameters->port_s = NULL;
    parameters->tls_session = tls_session;

    return parameters;
}

uk_ue_socket_client_connection_parameters *uk_ue_socket_client_connection_parameters_build_s(int fd, const char *domain,
    const char *host, const char *port, uk_crypto_tls_session *tls_session) {

    uk_ue_socket_client_connection_parameters *parameters;

    parameters = NULL;

    uk_utils_safe_alloc(parameters, uk_ue_socket_client_connection_parameters, 1);
    parameters->fd = fd;
    parameters->domain_s = domain;
    parameters->domain = -1;
    parameters->host = host;
    parameters->port_s = port;
    parameters->port = -1;
    parameters->tls_session = tls_session;

    return parameters;
}
