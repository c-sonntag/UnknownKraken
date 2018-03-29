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

#include <unknownecho/thread/thread.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/check_parameter.h>

#include <errno.h>

ue_thread_id *ue_thread_create(void *function, void *arg) {
    ue_thread_id *ti;
#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif

    ue_check_parameter_or_return(function);

    ue_safe_alloc(ti, ue_thread_id, 1);

#if defined(_WIN32) || defined(_WIN64)
    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        if (!(ti->id = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)function, arg, 0, NULL))) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return NULL;
        }
    _Pragma("GCC diagnostic pop")
    ue_thread_result_add(ti);
#else
        _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
            if (pthread_create(&ti->id, NULL, (void *(*)(void *))function, arg) != 0) {
                ue_stacktrace_push_errno();
                ue_safe_free(ti);
                return NULL;
            }
        _Pragma("GCC diagnostic pop")
#endif

    return ti;
}

bool ue_thread_join(ue_thread_id *ti, void **result) {
#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
        DWORD r;
#else
        int r;
#endif

    if (!ti || !ti->id) {
        ue_logger_warn("Specified thread ID is null. Maybe thread is already terminated.");
        return true;
    }

#if defined(_WIN32) || defined(_WIN64)
    ue_logger_debug("Before wait");
        r = WaitForSingleObject(ti->id, INFINITE);
        ue_logger_debug("r : %d", r);
        if (r == WAIT_FAILED) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            ue_safe_free(error_buffer);
            return false;
        }
        else if (r == WAIT_OBJECT_0) {
            if (ue_thread_results_is_initialized())
            {
                *result = ue_thread_result_get(ti);
            }
        }
#else
        if ((r = pthread_join(ti->id, &(*result))) != 0) {
            if (errno != 0) {
                ue_stacktrace_push_errno();
            } else {
                if (r == EDEADLK) {
                    ue_logger_error("A deadlock was detected");
                    ue_stacktrace_push_msg("A deadlock was detected");
                } else if (r == EINVAL) {
                    ue_logger_warn("Thread is not joinable or another thread is already waiting to join with this thread");
                    return true;
                } else if (r == ESRCH) {
                    ue_logger_error("No thread with the ID thread could be found");
                    ue_stacktrace_push_msg("No thread with the ID thread could be found");
                }
            }
            return false;
        }
#endif

    return true;
}

bool ue_thread_detach(ue_thread_id *ti) {
/*#if defined(_WIN32) || defined(_WIN64)
        char *error_buffer;
#endif*/

    ue_check_parameter_or_return(ti);

#if defined(_WIN32) || defined(_WIN64)
        /*if (!CloseHandle(ti->id)) {
            ue_get_last_werror(error_buffer);
            ue_stacktrace_push_msg(error_buffer);
            return false;
        }*/
#else
        if (!pthread_detach(ti->id) != 0) {
            //ue_stacktrace_push_errno();
            return false;
        }
#endif

    return true;
}

bool ue_thread_cancel(ue_thread_id *ti) {
#if defined(_WIN32) || defined(_WIN64)
    char *error_buffer;
#endif

    if (!ti) {
        ue_logger_warn("Thread already canceled");
        return true;
    }

#if defined(__unix__)
        pthread_cancel(ti->id);
        return true;
#elif defined(_WIN32) || defined(_WIN64)
    if (!CloseHandle(ti->id)) {
        ue_get_last_werror(error_buffer);
        ue_stacktrace_push_msg(error_buffer);
        return false;
    }
#endif

    return true;
}
