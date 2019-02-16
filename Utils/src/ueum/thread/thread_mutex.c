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

#include <ueum/thread/thread_mutex.h>
#include <ueum/safe/safe_alloc.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <ei/ei.h>
#endif

#include <errno.h>

/*
 * For Windows :
 * http://preshing.com/20111124/always-use-a-lightweight-mutex/
 */
ueum_thread_mutex *ueum_thread_mutex_create() {
    ueum_thread_mutex *m;
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    m = NULL;

    ueum_safe_alloc(m, ueum_thread_mutex, 1);

#if defined(_WIN32) || defined(_WIN64)
        InitializeCriticalSection(&m->lock);
        /*if (!(m->lock = CreateMutex(NULL, FALSE, NULL))) {
            ueum_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            ueum_safe_free(error_buffer);
            ueum_safe_free(m);
            return NULL;
        }*/
#else
        if (pthread_mutex_init(&m->lock, NULL) != 0) {
            ueum_safe_free(m);
            ei_stacktrace_push_errno();
            return NULL;
        }
#endif

    return m;
}

bool ueum_thread_mutex_destroy(ueum_thread_mutex *m) {
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
            ueum_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            ueum_safe_free(error_buffer);
            state = false;
        }*/
#else
        if (pthread_mutex_destroy(&m->lock) != 0) {
            ei_stacktrace_push_errno();
            state = false;
        }
#endif

    ueum_safe_free(m);

    return state;
}

bool ueum_thread_mutex_lock(ueum_thread_mutex *m) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ei_check_parameter_or_return(m)

#if defined(_WIN32) || defined(_WIN64)
        TryEnterCriticalSection(&m->lock);
        /*if (WaitForSingleObject(m->lock, INFINITE) == WAIT_FAILED) {
            ueum_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            ueum_safe_free(error_buffer);
            return false;
        }*/
#else
        if (pthread_mutex_lock(&m->lock) != 0) {
            ei_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}

bool ueum_thread_mutex_unlock(ueum_thread_mutex *m) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ei_check_parameter_or_return(m);

#if defined(_WIN32) || defined(_WIN64)
        LeaveCriticalSection(&m->lock);
        /*if (!ReleaseMutex(m->lock)) {
            ueum_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            ueum_safe_free(error_buffer);
            return false;
        }*/
#else
        if (pthread_mutex_unlock(&m->lock) != 0) {
            ei_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}
