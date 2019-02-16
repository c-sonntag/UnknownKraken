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

#ifndef UNKNOWNECHOUTILSMODULE_THREAD_RESULT_H
#define UNKNOWNECHOUTILSMODULE_THREAD_RESULT_H

#include <ueum/thread/thread_id_struct.h>
#include <ueum/compiler/bool.h>

typedef struct {
    ueum_thread_id *ti;
    void *result;
} ueum_thread_result;

#define THREAD_RESULTS_MAX 10

ueum_thread_result ueum_thread_results[THREAD_RESULTS_MAX];

void ueum_thread_results_init();

bool ueum_thread_results_is_initialized();

bool ueum_thread_result_exists(ueum_thread_id *ti);

void ueum_thread_result_add(ueum_thread_id *ti);

void ueum_thread_result_remove(ueum_thread_id *ti);

void ueum_thread_result_set(ueum_thread_id *ti, void *result);

void *ueum_thread_result_get(ueum_thread_id *ti);

#endif
