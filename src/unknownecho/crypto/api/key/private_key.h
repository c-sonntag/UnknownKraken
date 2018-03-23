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
 *  @file      private_key.h
 *  @brief     Private key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_PRIVATE_KEY_H
#define UNKNOWNECHO_PRIVATE_KEY_H

#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef enum {
	RSA_PRIVATE_KEY
} ue_private_key_type;

typedef struct ue_private_key ue_private_key;

ue_private_key *ue_private_key_create_from_impl(void *impl);

ue_private_key *ue_private_key_create(ue_private_key_type key_type, void *impl, int bits);

void ue_private_key_destroy(ue_private_key *sk);

int ue_private_key_size(ue_private_key *sk);

bool ue_private_key_is_valid(ue_private_key *sk);

void *ue_private_key_get_impl(ue_private_key *sk);

void *ue_private_key_get_rsa_impl(ue_private_key *sk);

bool ue_private_key_print(ue_private_key *sk, FILE *out_fd, unsigned char *passphrase, size_t passphrase_size);

#endif
