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

#ifndef UNKNOWNECHOUTILSMODULE_THREAD_H
#define UNKNOWNECHOUTILSMODULE_THREAD_H

#include <ueum/thread/thread_id_struct.h>
#include <ueum/compiler/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <ueum/thread/thread_result.h>
    #include <ei/ei.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <pthread.h>
#endif

ueum_thread_id *ueum_thread_create(void *function, void *arg);

bool ueum_thread_join(ueum_thread_id *ti, void **result);

bool ueum_thread_detach(ueum_thread_id *ti);

#if defined(_WIN32) || defined(_WIN64)
    #define ueum_get_current_thread_id() GetCurrentThreadId()
#else
    #define ueum_get_current_thread_id() pthread_self()
#endif

#define ueum_thread_resolve_current_id(ti) ti->id = ueum_get_current_thread_id();

#if defined(_WIN32) || defined(_WIN64)
    #define ueum_thread_begin(type, name) { type *name; ueum_thread_id *current;
#else
    #define ueum_thread_begin(type, name) type *name; {
#endif

#define ueum_thread_end_windows(r) \
    ueum_thread_resolve_current_id(current); \
    if (!ueum_thread_results_is_initialized()) { \
        ueum_thread_results_init(); \
    } \
    ueum_thread_result_set(current, (void *)r); \
    return NULL; \

#if defined(_WIN32) || defined(_WIN64)
    #define ueum_thread_exit(r) ueum_thread_end_windows(r)
#else
    #define ueum_thread_end(r) pthread_exit(r); }
#endif

bool ueum_thread_cancel(ueum_thread_id *ti);

#endif
