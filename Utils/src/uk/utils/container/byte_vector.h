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

#ifndef UnknownKrakenUtils_BYTE_VECTOR_H
#define UnknownKrakenUtils_BYTE_VECTOR_H

#include <uk/utils/compiler/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t size;
} uk_utils_byte_vector_element;

typedef struct {
    uk_utils_byte_vector_element **elements;
    int number;
} uk_utils_byte_vector;

uk_utils_byte_vector *uk_utils_byte_vector_create_empty();

void uk_utils_byte_vector_clean_up(uk_utils_byte_vector *vector);

void uk_utils_byte_vector_destroy(uk_utils_byte_vector *vector);

bool uk_utils_byte_vector_append_string(uk_utils_byte_vector *vector, const char *new_string);

bool uk_utils_byte_vector_append_bytes(uk_utils_byte_vector *vector, unsigned char *new_bytes, size_t new_bytes_size);

bool uk_utils_byte_vector_append_vector(uk_utils_byte_vector *from, uk_utils_byte_vector *to);

bool uk_utils_byte_vector_remove(uk_utils_byte_vector *vector, int index);

int uk_utils_byte_vector_size(uk_utils_byte_vector *vector);

uk_utils_byte_vector_element *uk_utils_byte_vector_get(uk_utils_byte_vector *vector, int index);

bool uk_utils_byte_vector_is_empty(uk_utils_byte_vector *vector);

bool uk_utils_byte_vector_print(uk_utils_byte_vector *vector, FILE *out);

bool uk_utils_byte_vector_print_element(uk_utils_byte_vector *vector, int index, FILE *out);

bool uk_utils_byte_vector_contains(uk_utils_byte_vector *vector, unsigned char *target, size_t target_size);

bool uk_utils_byte_vector_element_print_string(uk_utils_byte_vector_element *element, FILE *out);

#endif
