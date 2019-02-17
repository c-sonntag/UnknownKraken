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

#ifndef UnknownKrakenUtils_THREAD_H
#define UnknownKrakenUtils_THREAD_H

#include <uk/utils/thread/thread_id_struct.h>
#include <uk/utils/compiler/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <uk/utils/thread/thread_result.h>
    #include <uk/utils/ei.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <pthread.h>
#endif

uk_utils_thread_id *uk_utils_thread_create(void *function, void *arg);

bool uk_utils_thread_join(uk_utils_thread_id *ti, void **result);

bool uk_utils_thread_detach(uk_utils_thread_id *ti);

#if defined(_WIN32) || defined(_WIN64)
    #define uk_utils_get_current_thread_id() GetCurrentThreadId()
#else
    #define uk_utils_get_current_thread_id() pthread_self()
#endif

#define uk_utils_thread_resolve_current_id(ti) ti->id = uk_utils_get_current_thread_id();

#if defined(_WIN32) || defined(_WIN64)
    #define uk_utils_thread_begin(type, name) { type *name; uk_utils_thread_id *current;
#else
    #define uk_utils_thread_begin(type, name) type *name; {
#endif

#define uk_utils_thread_end_windows(r) \
    uk_utils_thread_resolve_current_id(current); \
    if (!uk_utils_thread_results_is_initialized()) { \
        uk_utils_thread_results_init(); \
    } \
    uk_utils_thread_result_set(current, (void *)r); \
    return NULL; \

#if defined(_WIN32) || defined(_WIN64)
    #define uk_utils_thread_exit(r) uk_utils_thread_end_windows(r)
#else
    #define uk_utils_thread_end(r) pthread_exit(r); }
#endif

bool uk_utils_thread_cancel(uk_utils_thread_id *ti);

#endif
