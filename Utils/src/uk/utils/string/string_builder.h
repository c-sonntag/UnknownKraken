/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#ifndef UnknownKrakenUtils_STRING_BUILDER_H
#define UnknownKrakenUtils_STRING_BUILDER_H

#include <uk/utils/compiler/bool.h>

#include <stddef.h>

typedef struct {
    char *data;
    size_t max_size;
    size_t position;
} uk_utils_string_builder;

uk_utils_string_builder *uk_utils_string_builder_create();

uk_utils_string_builder *uk_utils_string_builder_create_size(size_t max_size);

bool uk_utils_string_builder_append(uk_utils_string_builder *s, char *data, size_t data_len);

bool uk_utils_string_builder_append_variadic(uk_utils_string_builder *s, const char *format, ...);

void uk_utils_string_builder_clean_up(uk_utils_string_builder *s);

void uk_utils_string_builder_destroy(uk_utils_string_builder *s);

char *uk_utils_string_builder_get_data(uk_utils_string_builder *s);

size_t uk_utils_string_builder_get_position(uk_utils_string_builder *s);

#endif
