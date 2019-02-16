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

#ifndef UNKNOWNECHOUTILSMODULE_THREAD_MUTEX_H
#define UNKNOWNECHOUTILSMODULE_THREAD_MUTEX_H

#include <ueum/compiler/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <pthread.h>
#endif

typedef struct {
#if defined(_WIN32) || defined(_WIN64)
        //HANDLE lock;
        CRITICAL_SECTION lock;
#else
        pthread_mutex_t lock;
#endif
} ueum_thread_mutex;

ueum_thread_mutex *ueum_thread_mutex_create();

/**
 * @todo In UNIX impl, detect EBUSY and try to destroy the mutex with a timeout.
 */
bool ueum_thread_mutex_destroy(ueum_thread_mutex *m);

bool ueum_thread_mutex_lock(ueum_thread_mutex *m);

bool ueum_thread_mutex_unlock(ueum_thread_mutex *m);

#endif
