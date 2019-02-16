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

#include <ueum/thread/thread_cond.h>
#include <ueum/safe/safe_alloc.h>

#include <ei/ei.h>

#include <errno.h>

ueum_thread_cond *ueum_thread_cond_create() {
    ueum_thread_cond *cond;

    cond = NULL;

    ueum_safe_alloc(cond, ueum_thread_cond, 1);

#if defined(_WIN32) || defined(_WIN64)
    InitializeConditionVariable(&cond->data);
#else
    if (pthread_cond_init(&cond->data, NULL) != 0) {
        ei_stacktrace_push_errno();
        ueum_safe_free(cond);
        return NULL;
    }
#endif

    return cond;
}

void ueum_thread_cond_destroy(ueum_thread_cond *cond) {
    if (cond) {
#if defined(_WIN32) || defined(_WIN64)

#else
        pthread_cond_destroy(&cond->data);
#endif
        ueum_safe_free(cond);
    }
}

bool ueum_thread_cond_wait(ueum_thread_cond *cond, ueum_thread_mutex *mutex) {
    ei_check_parameter_or_return(cond);
    ei_check_parameter_or_return(mutex);

#if defined(_WIN32) || defined(_WIN64)
    //SleepConditionVariableCS(&cond->data, &mutex->lock, INFINITE);
#else
    if (pthread_cond_wait(&cond->data, &mutex->lock) != 0) {
        if (errno != ETIMEDOUT) {
            ei_stacktrace_push_errno();
            return false;
        }
    }
#endif

    return true;
}

bool ueum_thread_cond_signal(ueum_thread_cond *cond) {
    ei_check_parameter_or_return(cond);

#if defined(_WIN32) || defined(_WIN64)
    WakeConditionVariable(&cond->data);
#else
    if (pthread_cond_signal(&cond->data) != 0) {
        ei_stacktrace_push_errno();
        return false;
    }
#endif

    return true;
}

bool ueum_thread_cond_broadcast(ueum_thread_cond *cond) {
    ei_check_parameter_or_return(cond);

#if defined(_WIN32) || defined(_WIN64)
    WakeAllConditionVariable(&cond->data);
#else
    if (pthread_cond_broadcast(&cond->data) != 0) {
        ei_stacktrace_push_errno();
        return false;
    }
#endif

    return true;
}
