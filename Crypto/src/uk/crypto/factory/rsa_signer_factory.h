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
 *  @file      rsa_signer_factory.h
 *  @brief     Factory to create RSA signer from key pair.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_RSA_SIGNER_FACTORY_H
#define UnknownKrakenCrypto_RSA_SIGNER_FACTORY_H

#include <uk/crypto/api/signature/signer.h>
#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/key/asym_key.h>

uk_crypto_signer *uk_crypto_rsa_signer_create(uk_crypto_public_key *pk, uk_crypto_private_key *sk, const char *digest_name);

uk_crypto_signer *uk_crypto_rsa_signer_create_default(uk_crypto_public_key *pk, uk_crypto_private_key *sk);

uk_crypto_signer *uk_crypto_rsa_signer_create_sha256(uk_crypto_public_key *pk, uk_crypto_private_key *sk);

uk_crypto_signer *uk_crypto_rsa_signer_create_from_pair(uk_crypto_asym_key *akey, const char *digest_name);

uk_crypto_signer *uk_crypto_rsa_signer_create_default_from_pair(uk_crypto_asym_key *akey);

uk_crypto_signer *uk_crypto_rsa_signer_create_sha256_from_pair(uk_crypto_asym_key *akey);

#endif
