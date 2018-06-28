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

/**
 *  @file      tls_context.h
 *  @brief     Represent the TLS context, used to build the TLS connection.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TLS_CONTEXT_H
#define UNKNOWNECHO_TLS_CONTEXT_H

#include <unknownecho/network/api/tls/tls_method.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

typedef struct uecm_tls_context uecm_tls_context;

uecm_tls_context *uecm_tls_context_create(uecm_tls_method *method);

void uecm_tls_context_destroy(uecm_tls_context *context);

//bool uecm_tls_context_load_certificates(uecm_tls_context *context, uecm_pkcs12_keystore *keystore, uecm_x509_certificate *ca_certificate);
bool uecm_tls_context_load_certificates(uecm_tls_context *context, uecm_pkcs12_keystore *keystore, uecm_x509_certificate **ca_certificates, int ca_certificate_count);

bool uecm_tls_context_load_certificates_from_path(uecm_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path);

const void *uecm_tls_context_get_impl(uecm_tls_context *context);

#endif
