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

/**
 *  @file      socket_client.h
 *  @brief     Handle socket client connection.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UnknownKrakenUnknownEcho_SOCKET_CLIENT_H
#define UnknownKrakenUnknownEcho_SOCKET_CLIENT_H

#include <uk/unknownecho/network/api/socket/socket_client_connection.h>
#include <uk/unknownecho/network/api/socket/socket_client_connection_parameters.h>
#include <uk/unknownecho/network/api/tls/tls_session.h>

uk_ue_socket_client_connection *uk_ue_socket_connect(uk_ue_socket_client_connection_parameters *parameter);

uk_ue_socket_client_connection *uk_ue_socket_connect_s(uk_ue_socket_client_connection_parameters *parameter);

#endif
