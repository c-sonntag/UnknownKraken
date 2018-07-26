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
 *  @brief     Stacktrace module to record error into ei_stacktrace struct.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef ERRORINTERCEPTOR_STRACKTRACE_H
#define ERRORINTERCEPTOR_STRACKTRACE_H

#include <ei/error/error.h>
#include <ei/error/internal_error.h>
#include <ei/stacktrace/stacktrace_struct.h>
#include <ei/bool.h>
#include <ei/thread/thread_storage.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

void ei_stacktrace_create(ei_stacktrace **stack);

void ei_stacktrace_destroy(ei_stacktrace *stack);

void push_to_stacktrace(ei_stacktrace *stack, ei_error *e);

char *ei_stacktrace_to_string(ei_stacktrace *stack);

void ei_stacktrace_print();

void ei_stacktrace_print_all();

void ei_stacktrace_print_fd_all(FILE *fd);

void ei_stacktrace_print_this(ei_stacktrace *stack);

void ei_stacktrace_print_fd(FILE *fd);

void ei_stacktrace_print_fd_this(ei_stacktrace *stack, FILE *fd);

char *ei_stacktrace_get_cause();

char *ei_stacktrace_get_cause_this(ei_stacktrace *stack);

bool ei_stacktrace_is_filled_this(ei_stacktrace *stack);

bool ei_stacktrace_is_filled();

void ei_stacktrace_clean_up();

#define ei_stacktrace_push_code(code) \
    char *description; \
    description = ei_internal_error_get_description(code); \
    push_to_stacktrace(ei_thread_storage_get_stacktrace(), ei_error_create((char *)__func__, __FILE__, __LINE__, description)); \
    free((void*)description); \

#define ei_stacktrace_push_errno() \
    char *description; \
    if (errno == 0) { \
        description = ei_internal_error_get_description(ERRORINTERCEPTOR_UNKNOWN_ERROR); \
        push_to_stacktrace(ei_thread_storage_get_stacktrace(), ei_error_create((char *)__func__, __FILE__, __LINE__, description)); \
        free((void*)description); \
    } else { \
        push_to_stacktrace(ei_thread_storage_get_stacktrace(), ei_error_create((char *)__func__, __FILE__, __LINE__, strerror(errno))); \
    } \

#define ei_stacktrace_push_msg(...) \
    push_to_stacktrace(ei_thread_storage_get_stacktrace(), ei_error_create_variadic((char *)__func__, __FILE__, __LINE__, __VA_ARGS__)); \

#endif
