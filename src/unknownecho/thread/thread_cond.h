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
 *  @file      thread_cond.h
 *  @brief     Portable structure of thread condition variable.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_THREAD_COND_H
#define UNKNOWNECHO_THREAD_COND_H

#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_mutex.h>

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
} ue_thread_cond;

ue_thread_cond *ue_thread_cond_create();

void ue_thread_cond_destroy(ue_thread_cond *cond);

bool ue_thread_cond_wait(ue_thread_cond *cond, ue_thread_mutex *mutex);

bool ue_thread_cond_signal(ue_thread_cond *cond);

bool ue_thread_cond_broadcast(ue_thread_cond *cond);

#endif
