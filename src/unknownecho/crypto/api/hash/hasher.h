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
 *  @file      hasher.h
 *  @brief     Hasher structure to hash message.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_HASHER_H
#define UNKNOWNECHO_HASHER_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct ue_hasher ue_hasher;

ue_hasher *ue_hasher_create();

void ue_hasher_destroy(ue_hasher *h);

bool ue_hasher_init(ue_hasher *h, const char *digest_name);

unsigned char *ue_hasher_digest(ue_hasher *h, const unsigned char *message, size_t message_len, size_t *digest_len);

int ue_hasher_get_digest_size(ue_hasher *h);

#endif
