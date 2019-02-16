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

#ifndef UNKNOWNECHOUTILSMODULE_FILE_UTILITY_H
#define UNKNOWNECHOUTILSMODULE_FILE_UTILITY_H

#include <stddef.h>
#include <stdio.h>

#include <ueum/compiler/bool.h>
#include <ueum/compiler/ssize_t.h>

bool ueum_is_file_exists(const char *file_name);

ssize_t ueum_get_file_size(FILE *fd);

char *ueum_read_file(const char *file_name);

bool ueum_write_file(const char *file_name, const char *data);

unsigned char *ueum_read_binary_file(const char *file_name, size_t *size);

bool ueum_write_binary_file(const char *file_name, unsigned char *data, size_t size);

#endif
