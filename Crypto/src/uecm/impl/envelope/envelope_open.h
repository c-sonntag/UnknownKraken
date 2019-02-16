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

#ifndef UNKNOWNECHOCRYPTOMODULE_ENVELOPE_OPEN_H
#define UNKNOWNECHOCRYPTOMODULE_ENVELOPE_OPEN_H

#include <openssl/evp.h>

#include <ueum/ueum.h>

bool envelope_open_buffer(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
    unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
    unsigned char **plaintext, int *plaintext_len, const char *cipher_name);

#endif
