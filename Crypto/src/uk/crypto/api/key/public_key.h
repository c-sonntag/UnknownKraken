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
 *  @file      public_key.h
 *  @brief     Public key structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_PUBLIC_KEY_H
#define UnknownKrakenCrypto_PUBLIC_KEY_H

#include <uk/utils/ueum.h>

#include <stdio.h>

typedef enum {
    RSA_PUBLIC_KEY
} uk_crypto_public_key_type;

typedef struct uk_crypto_public_key uk_crypto_public_key;

uk_crypto_public_key *uk_crypto_public_key_create(uk_crypto_public_key_type key_type, void *impl, int bits);

void uk_crypto_public_key_destroy(uk_crypto_public_key *pk);

int uk_crypto_public_key_size(uk_crypto_public_key *pk);

//bool uk_crypto_public_key_is_valid(uk_crypto_public_key *pk);

void *uk_crypto_public_key_get_impl(uk_crypto_public_key *pk);

void *uk_crypto_public_key_get_rsa_impl(uk_crypto_public_key *pk);

bool uk_crypto_public_key_print(uk_crypto_public_key *pk, FILE *out_fd);

#endif
