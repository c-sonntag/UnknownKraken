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
 *  @file      string_builder.h
 *  @brief     A string builder is a stream of string use to concatenate easily
 *             several types into a single string.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_STRING_BUILDER_H
#define UNKNOWNECHO_STRING_BUILDER_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
    char *data;
    size_t max_size;
    size_t position;
} ue_string_builder;

ue_string_builder *ue_string_builder_create();

ue_string_builder *ue_string_builder_create_size(size_t max_size);

bool ue_string_builder_append(ue_string_builder *s, char *data, size_t data_len);

bool ue_string_builder_append_variadic(ue_string_builder *s, const char *format, ...);

void ue_string_builder_clean_up(ue_string_builder *s);

void ue_string_builder_destroy(ue_string_builder *s);

char *ue_string_builder_get_data(ue_string_builder *s);

size_t ue_string_builder_get_position(ue_string_builder *s);

#endif
