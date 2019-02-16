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

#ifndef UNKNOWNECHOUTILSMODULE_THREAD_COND_H
#define UNKNOWNECHOUTILSMODULE_THREAD_COND_H

#include <ueum/compiler/bool.h>
#include <ueum/thread/thread_mutex.h>

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
} ueum_thread_cond;

ueum_thread_cond *ueum_thread_cond_create();

void ueum_thread_cond_destroy(ueum_thread_cond *cond);

bool ueum_thread_cond_wait(ueum_thread_cond *cond, ueum_thread_mutex *mutex);

bool ueum_thread_cond_signal(ueum_thread_cond *cond);

bool ueum_thread_cond_broadcast(ueum_thread_cond *cond);

#endif
