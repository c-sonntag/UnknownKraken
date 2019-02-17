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
 *  @file      hasher_factory.h
 *  @brief     Factory that create an Hasher (default is SHA-256).
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_HASHER_FACTORY_H
#define UnknownKrakenCrypto_HASHER_FACTORY_H

#include <uk/crypto/api/hash/hasher.h>

uk_crypto_hasher *uk_crypto_hasher_sha256_create();

uk_crypto_hasher *uk_crypto_hasher_default_create();

#endif
