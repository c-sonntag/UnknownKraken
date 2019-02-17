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
 *  @file      sym_encrypter_factory.h
 *  @brief     Factory to create Symmetric Encrypter from Symmetric Key (default is AES-CBC-256).
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_SYM_ENCRYPTER_FACTORY_H
#define UnknownKrakenCrypto_SYM_ENCRYPTER_FACTORY_H

#include <uk/crypto/api/encryption/sym_encrypter.h>
#include <uk/crypto/api/key/sym_key.h>

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_aes_cbc_create(uk_crypto_sym_key *key);

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_rc4_create(uk_crypto_sym_key *key);

uk_crypto_sym_encrypter *uk_crypto_sym_encrypter_default_create(uk_crypto_sym_key *key);

#endif
