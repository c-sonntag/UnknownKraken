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

#ifndef UnknownKrakenUnknownEcho_TLS_CONTEXT_H
#define UnknownKrakenUnknownEcho_TLS_CONTEXT_H

#include <uk/unknownecho/network/api/tls/tls_method.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>

typedef struct uk_crypto_tls_context uk_crypto_tls_context;

uk_crypto_tls_context *uk_crypto_tls_context_create(uk_crypto_tls_method *method);

void uk_crypto_tls_context_destroy(uk_crypto_tls_context *context);

//bool uk_crypto_tls_context_load_certificates(uk_crypto_tls_context *context, uk_crypto_pkcs12_keystore *keystore, uk_crypto_x509_certificate *ca_certificate);
bool uk_crypto_tls_context_load_certificates(uk_crypto_tls_context *context, uk_crypto_pkcs12_keystore *keystore, uk_crypto_x509_certificate **ca_certificates, int ca_certificate_count);

bool uk_crypto_tls_context_load_certificates_from_path(uk_crypto_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path);

const void *uk_crypto_tls_context_get_impl(uk_crypto_tls_context *context);

#endif
