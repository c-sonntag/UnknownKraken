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
 *  @file      thread_mutex.h
 *  @brief     Portable structure of thread mutex.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenUtils_THREAD_MUTEX_H
#define UnknownKrakenUtils_THREAD_MUTEX_H

#include <uk/utils/compiler/bool.h>

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
} uk_utils_thread_mutex;

uk_utils_thread_mutex *uk_utils_thread_mutex_create();

/**
 * @todo In UNIX impl, detect EBUSY and try to destroy the mutex with a timeout.
 */
bool uk_utils_thread_mutex_destroy(uk_utils_thread_mutex *m);

bool uk_utils_thread_mutex_lock(uk_utils_thread_mutex *m);

bool uk_utils_thread_mutex_unlock(uk_utils_thread_mutex *m);

#endif
