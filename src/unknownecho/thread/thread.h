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
 *  @file      thread.h
 *  @brief     Portable way of thread functions manipulation.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_THREAD_H
#define UNKNOWNECHO_THREAD_H

#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/bool.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <unknownecho/thread/thread_result.h>
    #include <unknownecho/errorHandling/error.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__unix__)
    #include <pthread.h>
#endif

ue_thread_id *ue_thread_create(void *function, void *arg);

bool ue_thread_join(ue_thread_id *ti, void **result);

bool ue_thread_detach(ue_thread_id *ti);

#if defined(_WIN32) || defined(_WIN64)
    #define ue_get_current_thread_id() GetCurrentThreadId()
#else
    #define ue_get_current_thread_id() pthread_self()
#endif

#define ue_thread_resolve_current_id(ti) ti->id = ue_get_current_thread_id();

#if defined(_WIN32) || defined(_WIN64)
    #define ue_thread_begin(type, name) { type *name; ue_thread_id *current;
#else
    #define ue_thread_begin(type, name) type *name; {
#endif

#define ue_thread_end_windows(r) \
    ue_thread_resolve_current_id(current); \
    if (!ue_thread_results_is_initialized()) { \
        ue_thread_results_init(); \
    } \
    ue_thread_result_set(current, (void *)r); \
    return NULL; \

#if defined(_WIN32) || defined(_WIN64)
    #define ue_thread_exit(r) ue_thread_end_windows(r)
#else
    #define ue_thread_end(r) pthread_exit(r); }
#endif

bool ue_thread_cancel(ue_thread_id *ti);

#endif
