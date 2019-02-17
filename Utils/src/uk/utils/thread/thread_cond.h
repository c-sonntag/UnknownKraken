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

#ifndef UnknownKrakenUtils_THREAD_COND_H
#define UnknownKrakenUtils_THREAD_COND_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/thread/thread_mutex.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <pthread.h>
#endif

typedef struct {
#if defined(_WIN32) || defined(_WIN64)
        CONDITION_VARIABLE data;
#elif defined(__unix__)
        pthread_cond_t data;
#endif
} uk_utils_thread_cond;

uk_utils_thread_cond *uk_utils_thread_cond_create();

void uk_utils_thread_cond_destroy(uk_utils_thread_cond *cond);

bool uk_utils_thread_cond_wait(uk_utils_thread_cond *cond, uk_utils_thread_mutex *mutex);

bool uk_utils_thread_cond_signal(uk_utils_thread_cond *cond);

bool uk_utils_thread_cond_broadcast(uk_utils_thread_cond *cond);

#endif
