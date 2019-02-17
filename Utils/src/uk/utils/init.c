/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
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

#include <uk/utils/init.h>
#include <uk/utils/thread/thread_storage.h>
#include <uk/utils/compiler/bool.h>
#include <uk/utils/logger/logger_manager.h>

static bool uk_utils_thread_storage_initialized = false;

int uk_utils_init() {
    if (!uk_utils_thread_storage_initialized) {
        uk_utils_thread_storage_initialized = uk_utils_thread_storage_init();
    }

    uk_utils_logger_manager_init();

    return uk_utils_thread_storage_initialized;
}

void uk_utils_uninit() {
    uk_utils_logger_manager_uninit();

    if (uk_utils_thread_storage_initialized) {
        uk_utils_thread_storage_uninit();
    }
}
