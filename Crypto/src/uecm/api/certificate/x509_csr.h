/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
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
 *  @file      x509_csr.h
 *  @brief     Structure to represent an X509 CSR (Certificate Signing Request), in order
 *             to sign issuer certificate (like a client) by CA certificate (like a server).
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       https://en.wikipedia.org/wiki/Certificate_signing_request
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CSR_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CSR_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>
#include <ueum/ueum.h>

#include <stdio.h>
#include <stddef.h>

typedef struct uecm_x509_csr uecm_x509_csr;

uecm_x509_csr *uecm_x509_csr_create(uecm_x509_certificate *certificate, uecm_private_key *private_key);

void uecm_x509_csr_destroy(uecm_x509_csr *csr);

bool uecm_x509_csr_print(uecm_x509_csr *csr, FILE *fd);

char *uecm_x509_csr_to_string(uecm_x509_csr *csr);

uecm_x509_csr *uecm_x509_string_to_csr(char *string);

uecm_x509_csr *uecm_x509_bytes_to_csr(unsigned char *data, size_t data_size);

uecm_x509_certificate *uecm_x509_csr_sign(uecm_x509_csr *csr, uecm_private_key *private_key);

void *uecm_x509_csr_get_impl(uecm_x509_csr *csr);

#endif
