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

#ifndef UnknownKrakenCrypto_SYM_FILE_ENCRYPTION_H
#define UnknownKrakenCrypto_SYM_FILE_ENCRYPTION_H

#include <uk/crypto/api/key/sym_key.h>
#include <uk/utils/ueum.h>

bool uk_crypto_file_encrypt(const char *input_file_name, const char *output_file_name, uk_crypto_sym_key *key, unsigned char **iv, size_t *iv_size);

bool uk_crypto_file_decrypt(const char *input_file_name, const char *output_file_name, uk_crypto_sym_key *key, unsigned char *iv);

#endif
