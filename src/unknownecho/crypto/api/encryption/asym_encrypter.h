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
 *  @file      asym_encrypter.h
 *  @brief     Asymmetric Encrypter structure to encrypt/decrypt with public or private key.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_ASYM_ENCRYPTER_H
#define UNKNOWNECHO_ASYM_ENCRYPTER_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
	char *algorithm;
	ue_public_key *pk;
	ue_private_key *sk;
} ue_asym_encrypter;

ue_asym_encrypter *ue_asym_encrypter_create();

void ue_asym_encrypter_destroy(ue_asym_encrypter *encrypter);

void ue_asym_encrypter_destroy_all(ue_asym_encrypter *encrypter);

bool ue_asym_encrypter_init(ue_asym_encrypter *encrypter, const char *algorithm);

bool ue_asym_encrypter_set_pk(ue_asym_encrypter *encrypter, ue_public_key *pk);

bool ue_asym_encrypter_set_sk(ue_asym_encrypter *encrypter, ue_private_key *sk);

unsigned char *ue_asym_encrypter_public_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size);

unsigned char *ue_asym_encrypter_private_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size);

unsigned char *ue_asym_encrypter_private_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size);

unsigned char *ue_asym_encrypter_public_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size);

#endif
