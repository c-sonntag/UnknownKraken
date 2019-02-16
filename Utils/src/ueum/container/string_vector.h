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

#ifndef UNKNOWNECHOUTILSMODULE_STRING_VECTOR_H
#define UNKNOWNECHOUTILSMODULE_STRING_VECTOR_H

#include <ueum/compiler/bool.h>

#include <stdio.h>

typedef struct {
    char **elements;
    int number;
} ueum_string_vector;

ueum_string_vector *ueum_string_vector_create_empty();

void ueum_string_vector_clean_up(ueum_string_vector *v);

void ueum_string_vector_destroy(ueum_string_vector *v);

bool ueum_string_vector_append(ueum_string_vector *v, const char *new_string);

bool ueum_string_vector_append_vector(ueum_string_vector *from, ueum_string_vector *to);

bool ueum_string_vector_remove(ueum_string_vector *v, int index);

int ueum_string_vector_size(ueum_string_vector *v);

char *ueum_string_vector_get(ueum_string_vector *v, int index);

bool ueum_string_vector_is_empty(ueum_string_vector *v);

bool ueum_string_vector_print(ueum_string_vector *v, FILE *out);

bool ueum_string_vector_contains(ueum_string_vector *v, char *target);

#endif
