/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
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

/**
 *  @file      internal_error.h
 *  @brief     Internal error provides a set of common errors.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenUtils_INTERNAL_ERROR_H
#define UnknownKrakenUtils_INTERNAL_ERROR_H

#include <uk/utils/error/error.h>

#include <stdio.h>

typedef enum {
    UnknownKrakenUtils_SUCCESS,
    UnknownKrakenUtils_NO_SUCH_MEMORY,
    UnknownKrakenUtils_FILE_NOT_FOUND,
    UnknownKrakenUtils_INVALID_PARAMETER,
    UnknownKrakenUtils_NO_INTERNET_CONNECTION,
    UnknownKrakenUtils_UNKNOWN_ERROR
} uk_utils_internal_error_type;

char *uk_utils_internal_error_get_description(uk_utils_internal_error_type type);

char *uk_utils_internal_error_to_string(uk_utils_error *e);

void uk_utils_internal_error_print(uk_utils_error *e, FILE *out);

#endif
