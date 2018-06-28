/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

/**
 *  @file      sym_encrypter.h
 *  @brief     Symmetric Encrypter structure to encrypt/decrypt with unique key.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SYM_ENCRYPTER_H
#define UNKNOWNECHO_SYM_ENCRYPTER_H

#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct ue_sym_encrypter ue_sym_encrypter;

ue_sym_encrypter *ue_sym_encrypter_create(const char *cipher_name);

void ue_sym_encrypter_destroy(ue_sym_encrypter *encrypter);

void ue_sym_encrypter_destroy_all(ue_sym_encrypter *encrypter);

ue_sym_key *ue_sym_encrypter_get_key(ue_sym_encrypter *encrypter);

bool ue_sym_encrypter_set_key(ue_sym_encrypter *encrypter, ue_sym_key *key);

size_t ue_sym_encrypter_get_iv_size(ue_sym_encrypter *encrypter);

bool ue_sym_encrypter_encrypt(ue_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size);

bool ue_sym_encrypter_decrypt(ue_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size, unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size);

#endif
