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

#include <ueum/thread/thread.h>
#include <ueum/safe/safe_alloc.h>

#include <errno.h>

ueum_thread_id *ueum_thread_create(void *function, void *arg) {
    ueum_thread_id *ti;
#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
    error_buffer = NULL;
#endif

    ei_check_parameter_or_return(function);

    ti = NULL;

    ueum_safe_alloc(ti, ueum_thread_id, 1);

#if defined(_WIN32) || defined(_WIN64)
    if ((ti->id = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)function, arg, 0, NULL)) == NULL) {
        ei_get_last_werror(error_buffer);
        ei_stacktrace_push_msg(error_buffer);
        ueum_safe_free(error_buffer);
        return NULL;
    }
    ueum_thread_result_add(ti);
#else
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            if (pthread_create(&ti->id, NULL, (void *(*)(void *))function, arg) != 0) {
                ei_stacktrace_push_errno();
                ueum_safe_free(ti);
                return NULL;
            }
        _Pragma("GCC diagnostic pop")
#endif

    return ti;
}

bool ueum_thread_join(ueum_thread_id *ti, void **result) {
#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer = NULL;
        DWORD r;
#else
        int r;
#endif

    if (!ti || !ti->id) {
        ei_logger_warn("Specified thread ID is null. Maybe thread is already terminated.");
        return true;
    }

#if defined(_WIN32) || defined(_WIN64)
    ei_logger_debug("Before wait");
        r = WaitForSingleObject(ti->id, INFINITE);
        ei_logger_debug("r : %d", r);
        if (r == WAIT_FAILED) {
            ei_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            ueum_safe_free(error_buffer);
            return false;
        }
        else if (r == WAIT_OBJECT_0) {
            if (ueum_thread_results_is_initialized())
            {
                *result = ueum_thread_result_get(ti);
            }
        }
#else
        if ((r = pthread_join(ti->id, &(*result))) != 0) {
            if (errno != 0) {
                ei_stacktrace_push_errno();
            } else {
                if (r == EDEADLK) {
                    ei_logger_error("A deadlock was detected");
                    ei_stacktrace_push_msg("A deadlock was detected");
                } else if (r == EINVAL) {
                    ei_logger_warn("Thread is not joinable or another thread is already waiting to join with this thread");
                    return true;
                } else if (r == ESRCH) {
                    ei_logger_error("No thread with the ID thread could be found");
                    ei_stacktrace_push_msg("No thread with the ID thread could be found");
                }
            }
            return false;
        }
#endif

    return true;
}

bool ueum_thread_detach(ueum_thread_id *ti) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ei_check_parameter_or_return(ti);

#if defined(_WIN32) || defined(_WIN64)
        /*if (!CloseHandle(ti->id)) {
            ueum_get_last_werror(error_buffer);
            ei_stacktrace_push_msg(error_buffer);
            return false;
        }*/
#else
        if (!pthread_detach(ti->id) != 0) {
            //ei_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}

bool ueum_thread_cancel(ueum_thread_id *ti) {
#if defined(_WIN32) || defined(_WIN64)
    char *error_buffer;
    error_buffer = NULL;
#endif

    if (!ti) {
        ei_logger_warn("Thread already canceled");
        return true;
    }

#if defined(__unix__)
        pthread_cancel(ti->id);
        return true;
#elif defined(_WIN32) || defined(_WIN64)
    if (!CloseHandle(ti->id)) {
        ei_get_last_werror(error_buffer);
        ei_stacktrace_push_msg(error_buffer);
        return false;
    }
#endif

    return true;
}
