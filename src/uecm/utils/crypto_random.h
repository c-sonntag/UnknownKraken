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
 *  @file      crypto_random.h
 *  @brief     Generate crypto random bytes or specific size.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_CRYPTO_RANDOM_H
#define UNKNOWNECHOCRYPTOMODULE_CRYPTO_RANDOM_H

#include <ueum/ueum.h>

#include <stddef.h>

/**
 * @brief uecm_crypto_seed_prng
 * @return true if PRNG is seeded, false otherwise
 * @todo test on Windows
 *
 * OpenSSL makes sure that the PRNG state is unique for each thread.
 * On systems that provide /dev/urandom, the randomness device is used to seed the PRNG transparently.
 * However, on all other systems, the application is responsible for seeding the PRNG by calling RAND_add(),
 * RAND_egd(3) or RAND_load_file(3).
 *
 * source : https://wiki.openssl.org/index.php/Manual:RAND_add(3),
 *    https://wiki.openssl.org/index.php/Random_Numbers
 */
bool uecm_crypto_random_seed_prng();

bool uecm_crypto_random_bytes(unsigned char *buffer, size_t buffer_length);

#endif
