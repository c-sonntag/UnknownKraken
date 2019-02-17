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

#include <uk/utils/thread/thread_result.h>
#include <string.h>

bool uk_utils_thread_results_initialized = false;

void uk_utils_thread_results_init() {
    unsigned short int i;

    memset(&uk_utils_thread_results, 0, THREAD_RESULTS_MAX * sizeof(uk_utils_thread_result));

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        memset(&uk_utils_thread_results[i].ti, 0, sizeof(uk_utils_thread_id));
        memset(&uk_utils_thread_results[i].result, 0, sizeof(void *));
    }

    uk_utils_thread_results_initialized = true;
}

bool uk_utils_thread_results_is_initialized() {
    return uk_utils_thread_results_initialized;
}

bool uk_utils_thread_result_exists(uk_utils_thread_id *ti) {
    if (!uk_utils_thread_results_initialized) {
        return false;
    }

    unsigned short int i;

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (uk_utils_thread_results[i].ti == ti) {
            return true;
        }
    }

    return false;
}

void uk_utils_thread_result_add(uk_utils_thread_id *ti) {
    unsigned short int i;

    if (!uk_utils_thread_results_initialized || uk_utils_thread_result_exists(ti)) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (!uk_utils_thread_results[i].ti) {
            uk_utils_thread_results[i].ti = ti;
            break;
        }
    }
}

void uk_utils_thread_result_remove(uk_utils_thread_id *ti) {
    unsigned short int i;

    if (!uk_utils_thread_results_initialized) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (uk_utils_thread_results[i].ti == ti) {
            uk_utils_thread_results[i].ti = NULL;
            uk_utils_thread_results[i].result = NULL;
            break;
        }
    }
}

void uk_utils_thread_result_set(uk_utils_thread_id *ti, void *result) {
    unsigned short int i;

    if (!uk_utils_thread_results_initialized) {
        return;
    }

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (uk_utils_thread_results[i].ti == ti) {
            uk_utils_thread_results[i].result = result;
            break;
        }
    }
}

void *uk_utils_thread_result_get(uk_utils_thread_id *ti) {
    unsigned short int i;
    void *result;

    if (!uk_utils_thread_results_initialized) {
        return NULL;
    }

    result = NULL;

    for (i = 0; i < THREAD_RESULTS_MAX; i++) {
        if (uk_utils_thread_results[i].ti == ti) {
            result = uk_utils_thread_results[i].result;
            uk_utils_thread_results[i].ti = NULL;
            uk_utils_thread_results[i].result = NULL;
            break;
        }
    }

    return result;
}
