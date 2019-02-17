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
 *  @file      asym_key.h
 *  @brief     Asymmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_ASYM_KEY_H
#define UnknownKrakenCrypto_ASYM_KEY_H

#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/utils/ueum.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    uk_crypto_public_key *pk;
    uk_crypto_private_key *sk;
} uk_crypto_asym_key;

uk_crypto_asym_key *uk_crypto_asym_key_create(uk_crypto_public_key *pk, uk_crypto_private_key *sk);

void uk_crypto_asym_key_destroy(uk_crypto_asym_key *akey);

void uk_crypto_asym_key_destroy_all(uk_crypto_asym_key *akey);

//bool uk_crypto_asym_key_is_valid(uk_crypto_asym_key *akey);

bool uk_crypto_asym_key_print(uk_crypto_asym_key *akey, FILE *out_fd, char *passphrase);

#endif
