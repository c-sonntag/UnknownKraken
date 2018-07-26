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
 *  @copyright GNU Public License.
 */

#ifndef ERRORINTERCEPTOR_THREAD_MUTEX_H
#define ERRORINTERCEPTOR_THREAD_MUTEX_H

#include <ei/bool.h>

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
} ei_thread_mutex;

ei_thread_mutex *ei_thread_mutex_create();

/**
 * @todo In UNIX impl, detect EBUSY and try to destroy the mutex with a timeout.
 */
bool ei_thread_mutex_destroy(ei_thread_mutex *m);

bool ei_thread_mutex_lock(ei_thread_mutex *m);

bool ei_thread_mutex_unlock(ei_thread_mutex *m);

#endif
