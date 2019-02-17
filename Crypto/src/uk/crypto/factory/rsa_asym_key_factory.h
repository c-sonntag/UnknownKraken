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
 *  @file      rsa_asym_key_factory.h
 *  @brief     Factory to create RSA Asymmetric Key. Random, from files, from
 *             already existing certificate.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @todo      Add callback for RSA key generation
 */

#ifndef UnknownKrakenCrypto_RSA_ASYM_KEY_FACTORY_H
#define UnknownKrakenCrypto_RSA_ASYM_KEY_FACTORY_H

#include <uk/crypto/api/key/asym_key.h>
#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/certificate/x509_certificate.h>

uk_crypto_asym_key *uk_crypto_rsa_asym_key_create(int bits);

uk_crypto_public_key *uk_crypto_rsa_public_key_create_pk_from_file(char *file_path);

uk_crypto_private_key *uk_crypto_rsa_private_key_create_sk_from_file(char *file_path);

uk_crypto_asym_key *uk_crypto_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path);

uk_crypto_public_key *uk_crypto_rsa_public_key_from_x509_certificate(uk_crypto_x509_certificate *certificate);

uk_crypto_private_key *uk_crypto_rsa_private_key_from_key_certificate(const char *file_name);

#endif
