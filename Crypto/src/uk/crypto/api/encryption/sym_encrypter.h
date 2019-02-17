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
 *  @file      sym_encrypter.h
 *  @brief     Symmetric Encrypter structure to encrypt/decrypt with unique key.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_SYM_ENCRYPTER_H
#define UnknownKrakenCrypto_SYM_ENCRYPTER_H

#include <uk/crypto/api/key/sym_key.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

typedef struct uk_crypto_sym_encrypter uk_crypto_sym_encrypter;

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_create(const char *cipher_name);

void uk_crypto_sym_encrypter_destroy(uk_crypto_sym_encrypter *encrypter);

void uk_crypto_sym_encrypter_destroy_all(uk_crypto_sym_encrypter *encrypter);

uk_crypto_sym_key *uk_crypto_sym_encrypter_get_key(uk_crypto_sym_encrypter *encrypter);

bool uk_crypto_sym_encrypter_set_key(uk_crypto_sym_encrypter *encrypter, uk_crypto_sym_key *key);

size_t uk_crypto_sym_encrypter_get_iv_size(uk_crypto_sym_encrypter *encrypter);

bool uk_crypto_sym_encrypter_encrypt(uk_crypto_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size);

bool uk_crypto_sym_encrypter_decrypt(uk_crypto_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size, unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size);

#endif
