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
 *  @file      signer.h
 *  @brief     Signer structure that sign/verify binary data.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_SIGNER_H
#define UnknownKrakenCrypto_SIGNER_H

#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/utils/ueum.h>

#include <stddef.h>

typedef struct uk_crypto_signer uk_crypto_signer;

uk_crypto_signer *uk_crypto_signer_create(const char *digest_name);

void uk_crypto_signer_destroy(uk_crypto_signer *signer);

bool uk_crypto_signer_set_public_key(uk_crypto_signer *signer, uk_crypto_public_key *public_key);

bool uk_crypto_signer_set_private_key(uk_crypto_signer *signer, uk_crypto_private_key *private_key);

bool uk_crypto_signer_sign_buffer(uk_crypto_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char **signature, size_t *signature_length);

bool uk_crypto_signer_verify_buffer(uk_crypto_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length);

#endif
