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

#ifndef UnknownKrakenUtils_THREAD_RESULT_H
#define UnknownKrakenUtils_THREAD_RESULT_H

#include <uk/utils/thread/thread_id_struct.h>
#include <uk/utils/compiler/bool.h>

typedef struct {
    uk_utils_thread_id *ti;
    void *result;
} uk_utils_thread_result;

#define THREAD_RESULTS_MAX 10

uk_utils_thread_result uk_utils_thread_results[THREAD_RESULTS_MAX];

void uk_utils_thread_results_init();

bool uk_utils_thread_results_is_initialized();

bool uk_utils_thread_result_exists(uk_utils_thread_id *ti);

void uk_utils_thread_result_add(uk_utils_thread_id *ti);

void uk_utils_thread_result_remove(uk_utils_thread_id *ti);

void uk_utils_thread_result_set(uk_utils_thread_id *ti, void *result);

void *uk_utils_thread_result_get(uk_utils_thread_id *ti);

#endif
