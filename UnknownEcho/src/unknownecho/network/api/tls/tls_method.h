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
 *  @file      tls_method.h
 *  @brief     TLS method to specify the TLS handshake protocol.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TLS_METHOD_H
#define UNKNOWNECHO_TLS_METHOD_H

typedef struct uecm_tls_method uecm_tls_method;

uecm_tls_method *uecm_tls_method_create_client();

uecm_tls_method *uecm_tls_method_create_server();

void uecm_tls_method_destroy(uecm_tls_method *method);

const void *uecm_tls_method_get_impl(uecm_tls_method *method);

#endif
