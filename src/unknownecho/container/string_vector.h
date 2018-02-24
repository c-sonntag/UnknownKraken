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
 *  @file      string_vector.h
 *  @brief     A container that represent a vector of strings.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_STRING_VECTOR_H
#define UNKNOWNECHO_STRING_VECTOR_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef struct {
    char **elements;
    int number;
} ue_string_vector;

ue_string_vector *ue_string_vector_create_empty();

void ue_string_vector_clean_up(ue_string_vector *v);

void ue_string_vector_destroy(ue_string_vector *v);

bool ue_string_vector_append(ue_string_vector *v, const char *new_string);

bool ue_string_vector_append_vector(ue_string_vector *from, ue_string_vector *to);

bool ue_string_vector_remove(ue_string_vector *v, int index);

int ue_string_vector_size(ue_string_vector *v);

char *ue_string_vector_get(ue_string_vector *v, int index);

bool ue_string_vector_is_empty(ue_string_vector *v);

bool ue_string_vector_print(ue_string_vector *v, FILE *out);

bool ue_string_vector_contains(ue_string_vector *v, char *target);

#endif
