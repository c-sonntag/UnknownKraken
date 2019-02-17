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

#include <uk/utils/thread/thread_cond.h>
#include <uk/utils/safe/safe_alloc.h>

#include <uk/utils/ei.h>

#include <errno.h>

uk_utils_thread_cond *uk_utils_thread_cond_create() {
    uk_utils_thread_cond *cond;

    cond = NULL;

    uk_utils_safe_alloc(cond, uk_utils_thread_cond, 1);

#if defined(_WIN32) || defined(_WIN64)
    InitializeConditionVariable(&cond->data);
#else
    if (pthread_cond_init(&cond->data, NULL) != 0) {
        uk_utils_stacktrace_push_errno();
        uk_utils_safe_free(cond);
        return NULL;
    }
#endif

    return cond;
}

void uk_utils_thread_cond_destroy(uk_utils_thread_cond *cond) {
    if (cond) {
#if defined(_WIN32) || defined(_WIN64)

#else
        pthread_cond_destroy(&cond->data);
#endif
        uk_utils_safe_free(cond);
    }
}

bool uk_utils_thread_cond_wait(uk_utils_thread_cond *cond, uk_utils_thread_mutex *mutex) {
    uk_utils_check_parameter_or_return(cond);
    uk_utils_check_parameter_or_return(mutex);

#if defined(_WIN32) || defined(_WIN64)
    //SleepConditionVariableCS(&cond->data, &mutex->lock, INFINITE);
#else
    if (pthread_cond_wait(&cond->data, &mutex->lock) != 0) {
        if (errno != ETIMEDOUT) {
            uk_utils_stacktrace_push_errno();
            return false;
        }
    }
#endif

    return true;
}

bool uk_utils_thread_cond_signal(uk_utils_thread_cond *cond) {
    uk_utils_check_parameter_or_return(cond);

#if defined(_WIN32) || defined(_WIN64)
    WakeConditionVariable(&cond->data);
#else
    if (pthread_cond_signal(&cond->data) != 0) {
        uk_utils_stacktrace_push_errno();
        return false;
    }
#endif

    return true;
}

bool uk_utils_thread_cond_broadcast(uk_utils_thread_cond *cond) {
    uk_utils_check_parameter_or_return(cond);

#if defined(_WIN32) || defined(_WIN64)
    WakeAllConditionVariable(&cond->data);
#else
    if (pthread_cond_broadcast(&cond->data) != 0) {
        uk_utils_stacktrace_push_errno();
        return false;
    }
#endif

    return true;
}
