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

#ifndef UNKNOWNECHO_BYTE_VECTOR_H
#define UNKNOWNECHO_BYTE_VECTOR_H

#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t size;
} ue_byte_vector_element;

typedef struct {
    ue_byte_vector_element **elements;
    int number;
} ue_byte_vector;

ue_byte_vector *ue_byte_vector_create_empty();

void ue_byte_vector_clean_up(ue_byte_vector *vector);

void ue_byte_vector_destroy(ue_byte_vector *vector);

bool ue_byte_vector_append_string(ue_byte_vector *vector, const char *new_string);

bool ue_byte_vector_append_bytes(ue_byte_vector *vector, unsigned char *new_bytes, size_t new_bytes_size);

bool ue_byte_vector_append_vector(ue_byte_vector *from, ue_byte_vector *to);

bool ue_byte_vector_remove(ue_byte_vector *vector, int index);

int ue_byte_vector_size(ue_byte_vector *vector);

ue_byte_vector_element *ue_byte_vector_get(ue_byte_vector *vector, int index);

bool ue_byte_vector_is_empty(ue_byte_vector *vector);

bool ue_byte_vector_print(ue_byte_vector *vector, FILE *out);

bool ue_byte_vector_print_element(ue_byte_vector *vector, int index, FILE *out);

bool ue_byte_vector_contains(ue_byte_vector *vector, unsigned char *target, size_t target_size);

#endif
