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
 *  @file      x509_certificate.h
 *  @brief     Structure to represent an X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       https://en.wikipedia.org/wiki/X.509
 *  @todo      parsing : https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 *  @todo      chain verification :
 *                - http://fm4dd.com/openssl/certverify.htm,
 *                - https://stackoverflow.com/questions/23407376/testing-x509-certificate-expiry-date-with-c
 *
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_H

#include <ueum/ueum.h>
#include <uecm/api/key/private_key.h>

#include <stdio.h>
#include <stddef.h>

typedef struct uecm_x509_certificate uecm_x509_certificate;

uecm_x509_certificate *uecm_x509_certificate_create_empty();

bool uecm_x509_certificate_load_from_file(const char *file_name, uecm_x509_certificate **certificate);

bool uecm_x509_certificate_load_from_files(const char *cert_file_name, const char *key_file_name, const char *password, uecm_x509_certificate **certificate, uecm_private_key **private_key);

uecm_x509_certificate *uecm_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size);

void uecm_x509_certificate_destroy(uecm_x509_certificate *certificate);

void *uecm_x509_certificate_get_impl(uecm_x509_certificate *certificate);

bool uecm_x509_certificate_set_impl(uecm_x509_certificate *certificate, void *impl);

bool uecm_x509_certificate_equals(uecm_x509_certificate *c1, uecm_x509_certificate *c2);

bool uecm_x509_certificate_print(uecm_x509_certificate *certificate, FILE *out_fd);

char *uecm_x509_certificate_to_pem_string(uecm_x509_certificate *certificate, size_t *result_size);

#endif
