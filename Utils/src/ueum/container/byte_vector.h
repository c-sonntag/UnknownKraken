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

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_VECTOR_H
#define UNKNOWNECHOUTILSMODULE_BYTE_VECTOR_H

#include <ueum/compiler/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t size;
} ueum_byte_vector_element;

typedef struct {
    ueum_byte_vector_element **elements;
    int number;
} ueum_byte_vector;

ueum_byte_vector *ueum_byte_vector_create_empty();

void ueum_byte_vector_clean_up(ueum_byte_vector *vector);

void ueum_byte_vector_destroy(ueum_byte_vector *vector);

bool ueum_byte_vector_append_string(ueum_byte_vector *vector, const char *new_string);

bool ueum_byte_vector_append_bytes(ueum_byte_vector *vector, unsigned char *new_bytes, size_t new_bytes_size);

bool ueum_byte_vector_append_vector(ueum_byte_vector *from, ueum_byte_vector *to);

bool ueum_byte_vector_remove(ueum_byte_vector *vector, int index);

int ueum_byte_vector_size(ueum_byte_vector *vector);

ueum_byte_vector_element *ueum_byte_vector_get(ueum_byte_vector *vector, int index);

bool ueum_byte_vector_is_empty(ueum_byte_vector *vector);

bool ueum_byte_vector_print(ueum_byte_vector *vector, FILE *out);

bool ueum_byte_vector_print_element(ueum_byte_vector *vector, int index, FILE *out);

bool ueum_byte_vector_contains(ueum_byte_vector *vector, unsigned char *target, size_t target_size);

bool ueum_byte_vector_element_print_string(ueum_byte_vector_element *element, FILE *out);

#endif
