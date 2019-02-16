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
