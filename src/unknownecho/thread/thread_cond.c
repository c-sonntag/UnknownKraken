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

#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/alloc.h>

#include <ei/ei.h>

#include <errno.h>

ue_thread_cond *ue_thread_cond_create() {
	ue_thread_cond *cond;

	ue_safe_alloc(cond, ue_thread_cond, 1);

#if defined(_WIN32) || defined(_WIN64)
    InitializeConditionVariable(&cond->data);
#else
    if (pthread_cond_init(&cond->data, NULL) != 0) {
        ei_stacktrace_push_errno();
        ue_safe_free(cond);
        return NULL;
    }
#endif

    return cond;
}

void ue_thread_cond_destroy(ue_thread_cond *cond) {
	if (cond) {
#if defined(_WIN32) || defined(_WIN64)

#else
            pthread_cond_destroy(&cond->data);
#endif
		ue_safe_free(cond);
	}
}

bool ue_thread_cond_wait(ue_thread_cond *cond, ue_thread_mutex *mutex) {
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

bool ue_thread_cond_signal(ue_thread_cond *cond) {
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

bool ue_thread_cond_broadcast(ue_thread_cond *cond) {
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
