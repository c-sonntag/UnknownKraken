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

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_UTILITY_H
#define UNKNOWNECHOUTILSMODULE_BYTE_UTILITY_H

#include <ueum/compiler/bool.h>

#include <stddef.h>

unsigned char *ueum_bytes_create_from_string(const char *str);

unsigned char *ueum_bytes_create_from_bytes(unsigned char *bytes, size_t size);

void ueum_int_to_bytes(int n, unsigned char *bytes);

bool ueum_bytes_to_int(unsigned char *bytes, int *n);

bool ueum_bytes_starts_with(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size);

bool ueum_bytes_contains(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size);

#endif
