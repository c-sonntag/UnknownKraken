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
 *  @copyright GNU Public License.
 */

#ifndef ERRORINTERCEPTOR_INTERNAL_ERROR_H
#define ERRORINTERCEPTOR_INTERNAL_ERROR_H

#include <ei/error/error.h>

#include <stdio.h>

typedef enum {
    ERRORINTERCEPTOR_SUCCESS,
    ERRORINTERCEPTOR_NO_SUCH_MEMORY,
    ERRORINTERCEPTOR_FILE_NOT_FOUND,
    ERRORINTERCEPTOR_INVALID_PARAMETER,
    ERRORINTERCEPTOR_NO_INTERNET_CONNECTION,
    ERRORINTERCEPTOR_UNKNOWN_ERROR
} ei_internal_error_type;

char *ei_internal_error_get_description(ei_internal_error_type type);

char *ei_internal_error_to_string(ei_error *e);

void ei_internal_error_print(ei_error *e, FILE *out);

#endif
