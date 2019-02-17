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

#ifndef UnknownKrakenCrypto_CRYPTO_METADATA_H
#define UnknownKrakenCrypto_CRYPTO_METADATA_H

#include <uk/crypto/api/key/sym_key.h>
#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/keystore/pkcs12_keystore.h>
#include <uk/utils/ueum.h>

typedef struct {
    uk_crypto_sym_key *sym_key;
    uk_crypto_x509_certificate *cipher_certificate, *signer_certificate;
    uk_crypto_public_key *cipher_pk, *signer_pk;
    uk_crypto_private_key *cipher_sk, *signer_sk;
    const char *cipher_name;
    const char *digest_name;
} uk_crypto_crypto_metadata;

uk_crypto_crypto_metadata *uk_crypto_crypto_metadata_create_empty();

void uk_crypto_crypto_metadata_destroy(uk_crypto_crypto_metadata *metadata);

void uk_crypto_crypto_metadata_destroy_all(uk_crypto_crypto_metadata *metadata);

uk_crypto_sym_key *uk_crypto_crypto_metadata_get_sym_key(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_sym_key(uk_crypto_crypto_metadata *metadata, uk_crypto_sym_key *key);

uk_crypto_x509_certificate *uk_crypto_crypto_metadata_get_cipher_certificate(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_cipher_certificate(uk_crypto_crypto_metadata *metadata, uk_crypto_x509_certificate *certificate);

uk_crypto_public_key *uk_crypto_crypto_metadata_get_cipher_public_key(uk_crypto_crypto_metadata *metadata);

uk_crypto_private_key *uk_crypto_crypto_metadata_get_cipher_private_key(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_cipher_private_key(uk_crypto_crypto_metadata *metadata, uk_crypto_private_key *sk);

uk_crypto_x509_certificate *uk_crypto_crypto_metadata_get_signer_certificate(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_signer_certificate(uk_crypto_crypto_metadata *metadata, uk_crypto_x509_certificate *certificate);

uk_crypto_public_key *uk_crypto_crypto_metadata_get_signer_public_key(uk_crypto_crypto_metadata *metadata);

uk_crypto_private_key *uk_crypto_crypto_metadata_get_signer_private_key(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_signer_private_key(uk_crypto_crypto_metadata *metadata, uk_crypto_private_key *sk);

const char *uk_crypto_crypto_metadata_get_cipher_name(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_cipher_name(uk_crypto_crypto_metadata *metadata, const char *cipher_name);

const char *uk_crypto_crypto_metadata_get_digest_name(uk_crypto_crypto_metadata *metadata);

bool uk_crypto_crypto_metadata_set_digest_name(uk_crypto_crypto_metadata *metadata, const char *digest_name);

bool uk_crypto_crypto_metadata_certificates_exists(const char *folder_name, const char *uid);

bool uk_crypto_crypto_metadata_exists(const char *folder_name, const char *uid);

bool uk_crypto_crypto_metadata_write_certificates(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid);

bool uk_crypto_crypto_metadata_read_certificates(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid);

bool uk_crypto_crypto_metadata_write(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password);

bool uk_crypto_crypto_metadata_read(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password);

#endif
