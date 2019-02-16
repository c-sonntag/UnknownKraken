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
 *  @file      thread_storage.h
 *  @brief     Singleton module to retreive an object per thread.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef ERRORINTERCEPTOR_THREAD_STORAGE_H
#define ERRORINTERCEPTOR_THREAD_STORAGE_H

#include <ei/bool.h>
#include <ei/stacktrace/stacktrace_struct.h>
#include <ei/logger/logger_struct.h>

bool ei_thread_storage_init();

void ei_thread_storage_uninit();

bool ei_thread_storage_append_to_be_deleted_data(void *data);

ei_stacktrace *ei_thread_storage_get_stacktrace();

ei_stacktrace **ei_thread_storage_get_all_stacktrace(int *number);

ei_stacktrace *ei_thread_storage_get_stacktrace_from_thread_id(long ei_thread_id);

bool ei_thread_storage_set_char_data(char *data);

char *ei_thread_storage_get_char_data();

bool ei_thread_storage_set_int_data(int data);

int ei_thread_storage_get_int_data();

ei_logger *ei_thread_storage_get_logger();

#endif
