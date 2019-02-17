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

#ifndef UnknownKrakenUtils_STRING_VECTOR_H
#define UnknownKrakenUtils_STRING_VECTOR_H

#include <uk/utils/compiler/bool.h>

#include <stdio.h>

typedef struct {
    char **elements;
    int number;
} uk_utils_string_vector;

uk_utils_string_vector *uk_utils_string_vector_create_empty();

void uk_utils_string_vector_clean_up(uk_utils_string_vector *v);

void uk_utils_string_vector_destroy(uk_utils_string_vector *v);

bool uk_utils_string_vector_append(uk_utils_string_vector *v, const char *new_string);

bool uk_utils_string_vector_append_vector(uk_utils_string_vector *from, uk_utils_string_vector *to);

bool uk_utils_string_vector_remove(uk_utils_string_vector *v, int index);

int uk_utils_string_vector_size(uk_utils_string_vector *v);

char *uk_utils_string_vector_get(uk_utils_string_vector *v, int index);

bool uk_utils_string_vector_is_empty(uk_utils_string_vector *v);

bool uk_utils_string_vector_print(uk_utils_string_vector *v, FILE *out);

bool uk_utils_string_vector_contains(uk_utils_string_vector *v, char *target);

#endif
