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
 *  @file      pkcs12_keystore.h
 *  @brief     PKCS12 keystore structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @details   - Little description : https://en.wikipedia.org/wiki/PKCS_12
 *             - RFC : https://tools.ietf.org/html/rfc7292
 */

#ifndef UnknownKrakenCrypto_PKCS12_KEYSTORE_H
#define UnknownKrakenCrypto_PKCS12_KEYSTORE_H

#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/utils/ueum.h>

typedef struct {
    uk_crypto_x509_certificate *certificate;
    uk_crypto_private_key *private_key;
    uk_crypto_x509_certificate **other_certificates;
    int other_certificates_number;
    char *friendly_name;
} uk_crypto_pkcs12_keystore;

uk_crypto_pkcs12_keystore *uk_crypto_pkcs12_keystore_create(uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key, const char *friendly_name);

uk_crypto_pkcs12_keystore *uk_crypto_pkcs12_keystore_load(const char *file_name, const char *passphrase);

void uk_crypto_pkcs12_keystore_destroy(uk_crypto_pkcs12_keystore *keystore);

void uk_crypto_pkcs12_keystore_destroy_all(uk_crypto_pkcs12_keystore *keystore);

bool uk_crypto_pkcs12_keystore_add_certificate(uk_crypto_pkcs12_keystore *keystore, uk_crypto_x509_certificate *certificate, const unsigned char *friendly_name, size_t friendly_name_size);

bool uk_crypto_pkcs12_keystore_add_certificate_from_file(uk_crypto_pkcs12_keystore *keystore, const char *file_name, const unsigned char *friendly_name, size_t friendly_name_size);

bool uk_crypto_pkcs12_keystore_add_certificate_from_bytes(uk_crypto_pkcs12_keystore *keystore, unsigned char *data, size_t data_size, const unsigned char *friendly_name,
    size_t friendly_name_size);

bool uk_crypto_pkcs12_keystore_add_certificates_bundle(uk_crypto_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

bool uk_crypto_pkcs12_keystore_remove_certificate(uk_crypto_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

uk_crypto_x509_certificate *uk_crypto_pkcs12_keystore_find_certificate_by_friendly_name(uk_crypto_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

bool uk_crypto_pkcs12_keystore_write(uk_crypto_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

bool uk_crypto_pkcs12_keystore_print(uk_crypto_pkcs12_keystore *keystore, const char *passphrase);

#endif
