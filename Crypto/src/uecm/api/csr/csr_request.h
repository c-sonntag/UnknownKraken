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

#ifndef UNKNOWNECHOCRYPTOMODULE_CSR_REQUEST_H
#define UNKNOWNECHOCRYPTOMODULE_CSR_REQUEST_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/sym_key.h>

#include <stddef.h>

unsigned char *uecm_csr_build_client_request(uecm_x509_certificate *certificate, uecm_private_key *private_key,
    uecm_public_key *ca_public_key, size_t *cipher_data_size, uecm_sym_key *future_key, unsigned char *iv, size_t iv_size,
    const char *cipher_name, const char *digest_name);

uecm_x509_certificate *uecm_csr_process_server_response(unsigned char *server_response, size_t server_response_size, uecm_sym_key *key,
    unsigned char *iv, size_t iv_size);

unsigned char *uecm_csr_build_server_response(uecm_private_key *csr_private_key, uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, uecm_x509_certificate **signed_certificate,
    const char *cipher_name, const char *digest_name);

#endif
