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

#ifndef UnknownKrakenUnknownEcho_SOCKET_CLIENT_CONNECTION_PARAMETERS_H
#define UnknownKrakenUnknownEcho_SOCKET_CLIENT_CONNECTION_PARAMETERS_H

#include <uk/unknownecho/network/api/tls/tls_session.h>

typedef struct {
    int fd;
    int domain;
    const char *host, *domain_s, *port_s;
    unsigned short int port;
    uk_crypto_tls_session *tls_session;
} uk_ue_socket_client_connection_parameters;

uk_ue_socket_client_connection_parameters *uk_ue_socket_client_connection_parameters_build(int fd, int domain,
    const char *host, unsigned short int port, uk_crypto_tls_session *tls_session);

uk_ue_socket_client_connection_parameters *uk_ue_socket_client_connection_parameters_build_s(int fd, const char *domain,
    const char *host, const char *port, uk_crypto_tls_session *tls_session);

#endif
