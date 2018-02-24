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
#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>

typedef struct ue_tls_context ue_tls_context;

ue_tls_context *ue_tls_context_create(ue_tls_method *method);

void ue_tls_context_destroy(ue_tls_context *context);

bool ue_tls_context_load_certificates(ue_tls_context *context, ue_pkcs12_keystore *keystore, ue_x509_certificate *ca_certificate);

bool ue_tls_context_load_certificates_from_path(ue_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path);

const void *ue_tls_context_get_impl(ue_tls_context *context);

#endif
