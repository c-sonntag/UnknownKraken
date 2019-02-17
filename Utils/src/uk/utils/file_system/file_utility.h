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

#ifndef UnknownKrakenUtils_FILE_UTILITY_H
#define UnknownKrakenUtils_FILE_UTILITY_H

#include <stddef.h>
#include <stdio.h>

#include <uk/utils/compiler/bool.h>
#include <uk/utils/compiler/ssize_t.h>

bool uk_utils_is_file_exists(const char *file_name);

ssize_t uk_utils_get_file_size(FILE *fd);

char *uk_utils_read_file(const char *file_name);

bool uk_utils_write_file(const char *file_name, const char *data);

unsigned char *uk_utils_read_binary_file(const char *file_name, size_t *size);

bool uk_utils_write_binary_file(const char *file_name, unsigned char *data, size_t size);

#endif
