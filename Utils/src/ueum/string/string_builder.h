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

#ifndef UNKNOWNECHOUTILSMODULE_STRING_BUILDER_H
#define UNKNOWNECHOUTILSMODULE_STRING_BUILDER_H

#include <ueum/compiler/bool.h>

#include <stddef.h>

typedef struct {
    char *data;
    size_t max_size;
    size_t position;
} ueum_string_builder;

ueum_string_builder *ueum_string_builder_create();

ueum_string_builder *ueum_string_builder_create_size(size_t max_size);

bool ueum_string_builder_append(ueum_string_builder *s, char *data, size_t data_len);

bool ueum_string_builder_append_variadic(ueum_string_builder *s, const char *format, ...);

void ueum_string_builder_clean_up(ueum_string_builder *s);

void ueum_string_builder_destroy(ueum_string_builder *s);

char *ueum_string_builder_get_data(ueum_string_builder *s);

size_t ueum_string_builder_get_position(ueum_string_builder *s);

#endif
