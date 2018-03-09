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
 *  @file      data_cipher.h
 *  @brief     Data cipher that provides Integrity, Non-Repudiation and Authentification of datas, using Symmetric and Asymmetric Cryptography,
 *             Hashing, Compressing.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_DATA_CIPHER_H
#define UNKNOWNECHO_DATA_CIPHER_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/bool.h>

#include <stddef.h>

bool ue_cipher_plain_data(unsigned char *plain_data, size_t plain_data_size,
    ue_public_key *public_key, ue_private_key *private_key,
    unsigned char **cipher_data, size_t *cipher_data_size, const char *cipher_name,
    const char *digest_name);

bool ue_decipher_cipher_data(unsigned char *cipher_data,
    size_t cipher_data_size, ue_private_key *private_key,
    ue_public_key *public_key, unsigned char **plain_data,
    size_t *plain_data_size, const char *cipher_name,
    const char *digest_name);

#endif
