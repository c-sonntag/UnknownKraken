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
 *  @file      sym_key.h
 *  @brief     Symmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_SYM_KEY_H
#define UNKNOWNECHO_SYM_KEY_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
	unsigned char *data;
	size_t size;
} ue_sym_key;

ue_sym_key *ue_sym_key_create(unsigned char *data, size_t size);

void ue_sym_key_destroy(ue_sym_key *key);

size_t ue_sym_key_get_min_size();

bool ue_sym_key_is_valid(ue_sym_key *key);

#endif
