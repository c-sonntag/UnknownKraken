/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

/**
 *  @file      thread_mutex.h
 *  @brief     Portable structure of thread mutex.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_THREAD_MUTEX_H
#define UNKNOWNECHO_THREAD_MUTEX_H

#include <unknownecho/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <pthread.h>
#endif

typedef struct {
    #if defined(_WIN32) || defined(_WIN64)
        /* HANDLE lock; */
        CRITICAL_SECTION lock;
    #else
        pthread_mutex_t lock;
    #endif
} ue_thread_mutex;

ue_thread_mutex *ue_thread_mutex_create();

bool ue_thread_mutex_destroy(ue_thread_mutex *m);

bool ue_thread_mutex_lock(ue_thread_mutex *m);

bool ue_thread_mutex_unlock(ue_thread_mutex *m);

#endif
