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
 *  @file      stacktrace.h
 *  @brief     Stacktrace module to record error into uk_utils_stacktrace struct.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenUtils_STRACKTRACE_H
#define UnknownKrakenUtils_STRACKTRACE_H

#include <uk/utils/error/error.h>
#include <uk/utils/error/internal_error.h>
#include <uk/utils/stacktrace/stacktrace_struct.h>
#include <uk/utils/compiler/bool.h>
#include <uk/utils/thread/thread_storage.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

void uk_utils_stacktrace_create(uk_utils_stacktrace **stack);

void uk_utils_stacktrace_destroy(uk_utils_stacktrace *stack);

void push_to_stacktrace(uk_utils_stacktrace *stack, uk_utils_error *e);

char *uk_utils_stacktrace_to_string(uk_utils_stacktrace *stack);

void uk_utils_stacktrace_print();

void uk_utils_stacktrace_print_all();

void uk_utils_stacktrace_print_fd_all(FILE *fd);

void uk_utils_stacktrace_print_this(uk_utils_stacktrace *stack);

void uk_utils_stacktrace_print_fd(FILE *fd);

void uk_utils_stacktrace_print_fd_this(uk_utils_stacktrace *stack, FILE *fd);

char *uk_utils_stacktrace_get_cause();

char *uk_utils_stacktrace_get_cause_this(uk_utils_stacktrace *stack);

bool uk_utils_stacktrace_is_filled_this(uk_utils_stacktrace *stack);

bool uk_utils_stacktrace_is_filled();

void uk_utils_stacktrace_clean_up();

#define uk_utils_stacktrace_push_code(code) \
    char *description; \
    description = uk_utils_internal_error_get_description(code); \
    push_to_stacktrace(uk_utils_thread_storage_get_stacktrace(), uk_utils_error_create((char *)__func__, __FILE__, __LINE__, description)); \
    free((void*)description); \

#define uk_utils_stacktrace_push_errno() \
    char *description; \
    if (errno == 0) { \
        description = uk_utils_internal_error_get_description(UnknownKrakenUtils_UNKNOWN_ERROR); \
        push_to_stacktrace(uk_utils_thread_storage_get_stacktrace(), uk_utils_error_create((char *)__func__, __FILE__, __LINE__, description)); \
        free((void*)description); \
    } else { \
        push_to_stacktrace(uk_utils_thread_storage_get_stacktrace(), uk_utils_error_create((char *)__func__, __FILE__, __LINE__, strerror(errno))); \
    } \

#define uk_utils_stacktrace_push_msg(...) \
    push_to_stacktrace(uk_utils_thread_storage_get_stacktrace(), uk_utils_error_create_variadic((char *)__func__, __FILE__, __LINE__, __VA_ARGS__)); \

#endif
