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
 *  @file      sym_encrypter.h
 *  @brief     Symmetric Encrypter structure to encrypt/decrypt with unique key.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_H

#include <uecm/api/key/sym_key.h>
#include <ueum/ueum.h>

#include <stddef.h>

typedef struct uecm_sym_encrypter uecm_sym_encrypter;

uecm_sym_encrypter *uecm_sym_encrypter_create(const char *cipher_name);

void uecm_sym_encrypter_destroy(uecm_sym_encrypter *encrypter);

void uecm_sym_encrypter_destroy_all(uecm_sym_encrypter *encrypter);

uecm_sym_key *uecm_sym_encrypter_get_key(uecm_sym_encrypter *encrypter);

bool uecm_sym_encrypter_set_key(uecm_sym_encrypter *encrypter, uecm_sym_key *key);

size_t uecm_sym_encrypter_get_iv_size(uecm_sym_encrypter *encrypter);

bool uecm_sym_encrypter_encrypt(uecm_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size);

bool uecm_sym_encrypter_decrypt(uecm_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size, unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size);

#endif
