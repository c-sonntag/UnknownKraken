/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
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
