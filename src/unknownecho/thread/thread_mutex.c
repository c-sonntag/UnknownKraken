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

#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <unknownecho/errorHandling/error.h>
#endif

#include <errno.h>

/*
 * For Windows :
 * http://preshing.com/20111124/always-use-a-lightweight-mutex/
 */
ue_thread_mutex *ue_thread_mutex_create() {
    ue_thread_mutex *m;
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ue_safe_alloc(m, ue_thread_mutex, 1);

#if defined(_WIN32) || defined(_WIN64)
        InitializeCriticalSection(&m->lock);
        /*if (!(m->lock = CreateMutex(NULL, FALSE, NULL))) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            ue_safe_free(m);
            return NULL;
        }*/
#else
        if (pthread_mutex_init(&m->lock, NULL) != 0) {
            ue_safe_free(m);
            ue_stacktrace_push_errno();
            return NULL;
        }
#endif

    return m;
}

#include <excpt.h>

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {

puts("in filter.");

if (code == EXCEPTION_ACCESS_VIOLATION) {

puts("caught AV as expected.");

return EXCEPTION_EXECUTE_HANDLER;

}

else {

puts("didn't catch AV, unexpected.");

return EXCEPTION_CONTINUE_SEARCH;

};

}

bool ue_thread_mutex_destroy(ue_thread_mutex *m) {
    bool state;
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    if (!m) {
        return true;
    }

    state = true;

#if defined(_WIN32) || defined(_WIN64)
        DeleteCriticalSection(&m->lock);
        /*if (!CloseHandle(m->lock)) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            state = false;
        }*/
#else
        if (pthread_mutex_destroy(&m->lock) != 0) {
            ue_stacktrace_push_errno();
            state = false;
        }
#endif

    ue_safe_free(m);

    return state;
}

bool ue_thread_mutex_lock(ue_thread_mutex *m) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ue_check_parameter_or_return(m)

#if defined(_WIN32) || defined(_WIN64)
        TryEnterCriticalSection(&m->lock);
        /*if (WaitForSingleObject(m->lock, INFINITE) == WAIT_FAILED) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }*/
#else
        if (pthread_mutex_lock(&m->lock) != 0) {
            ue_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}

bool ue_thread_mutex_unlock(ue_thread_mutex *m) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ue_check_parameter_or_return(m);

#if defined(_WIN32) || defined(_WIN64)
        LeaveCriticalSection(&m->lock);
        /*if (!ReleaseMutex(m->lock)) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }*/
#else
        if (pthread_mutex_unlock(&m->lock) != 0) {
            ue_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}
