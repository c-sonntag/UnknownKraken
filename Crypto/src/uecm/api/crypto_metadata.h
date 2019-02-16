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

#ifndef UNKNOWNECHOCRYPTOMODULE_CRYPTO_METADATA_H
#define UNKNOWNECHOCRYPTOMODULE_CRYPTO_METADATA_H

#include <uecm/api/key/sym_key.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/keystore/pkcs12_keystore.h>
#include <ueum/ueum.h>

typedef struct {
    uecm_sym_key *sym_key;
    uecm_x509_certificate *cipher_certificate, *signer_certificate;
    uecm_public_key *cipher_pk, *signer_pk;
    uecm_private_key *cipher_sk, *signer_sk;
    const char *cipher_name;
    const char *digest_name;
} uecm_crypto_metadata;

uecm_crypto_metadata *uecm_crypto_metadata_create_empty();

void uecm_crypto_metadata_destroy(uecm_crypto_metadata *metadata);

void uecm_crypto_metadata_destroy_all(uecm_crypto_metadata *metadata);

uecm_sym_key *uecm_crypto_metadata_get_sym_key(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_sym_key(uecm_crypto_metadata *metadata, uecm_sym_key *key);

uecm_x509_certificate *uecm_crypto_metadata_get_cipher_certificate(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_cipher_certificate(uecm_crypto_metadata *metadata, uecm_x509_certificate *certificate);

uecm_public_key *uecm_crypto_metadata_get_cipher_public_key(uecm_crypto_metadata *metadata);

uecm_private_key *uecm_crypto_metadata_get_cipher_private_key(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_cipher_private_key(uecm_crypto_metadata *metadata, uecm_private_key *sk);

uecm_x509_certificate *uecm_crypto_metadata_get_signer_certificate(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_signer_certificate(uecm_crypto_metadata *metadata, uecm_x509_certificate *certificate);

uecm_public_key *uecm_crypto_metadata_get_signer_public_key(uecm_crypto_metadata *metadata);

uecm_private_key *uecm_crypto_metadata_get_signer_private_key(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_signer_private_key(uecm_crypto_metadata *metadata, uecm_private_key *sk);

const char *uecm_crypto_metadata_get_cipher_name(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_cipher_name(uecm_crypto_metadata *metadata, const char *cipher_name);

const char *uecm_crypto_metadata_get_digest_name(uecm_crypto_metadata *metadata);

bool uecm_crypto_metadata_set_digest_name(uecm_crypto_metadata *metadata, const char *digest_name);

bool uecm_crypto_metadata_certificates_exists(const char *folder_name, const char *uid);

bool uecm_crypto_metadata_exists(const char *folder_name, const char *uid);

bool uecm_crypto_metadata_write_certificates(uecm_crypto_metadata *metadata, const char *folder_name, const char *uid);

bool uecm_crypto_metadata_read_certificates(uecm_crypto_metadata *metadata, const char *folder_name, const char *uid);

bool uecm_crypto_metadata_write(uecm_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password);

bool uecm_crypto_metadata_read(uecm_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password);

#endif
