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
 *  @file      public_key.h
 *  @brief     Public key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_PUBLIC_KEY_H
#define UNKNOWNECHO_PUBLIC_KEY_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef enum {
	RSA_PUBLIC_KEY
} ue_public_key_type;

typedef struct ue_public_key ue_public_key;

ue_public_key *ue_public_key_create(ue_public_key_type key_type, void *impl, int bits);

void ue_public_key_destroy(ue_public_key *pk);

int ue_public_key_size(ue_public_key *pk);

bool ue_public_key_is_valid(ue_public_key *pk);

void *ue_public_key_get_impl(ue_public_key *pk);

void *ue_public_key_get_rsa_impl(ue_public_key *pk);

bool ue_public_key_print(ue_public_key *pk, FILE *out_fd);

#endif
