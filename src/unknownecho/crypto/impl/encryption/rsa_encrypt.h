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

#ifndef UNKNOWNECHO_RSA_ENCRYPT_H
#define UNKNOWNECHO_RSA_ENCRYPT_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>

#include <stddef.h>
#include <openssl/rsa.h>

unsigned char *ue_rsa_encrypt(RSA *pub_key, unsigned char *plaintext, int plaintext_len, int *ciphertext_len);

unsigned char *ue_rsa_decrypt(RSA *priv_key, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len);

unsigned char *ue_rsa_public_encrypt(ue_public_key *pk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding);

unsigned char *ue_rsa_private_decrypt(ue_private_key *sk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding);

unsigned char *ue_rsa_private_encrypt(ue_private_key *sk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding);

unsigned char *ue_rsa_public_decrypt(ue_public_key *pk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding);

#endif
