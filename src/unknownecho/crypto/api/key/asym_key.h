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
 *  @file      asym_key.h
 *  @brief     Asymmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_ASYM_KEY_H
#define UNKNOWNECHO_ASYM_KEY_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    ue_public_key *pk;
    ue_private_key *sk;
} ue_asym_key;

ue_asym_key *ue_asym_key_create(ue_public_key *pk, ue_private_key *sk);

void ue_asym_key_destroy(ue_asym_key *akey);

void ue_asym_key_destroy_all(ue_asym_key *akey);

bool ue_asym_key_is_valid(ue_asym_key *akey);

bool ue_asym_key_print(ue_asym_key *akey, FILE *out_fd, char *passphrase);

#endif
