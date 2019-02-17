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

#include <uk/utils/logger/logger_manager.h>
#include <uk/utils/thread/thread_storage.h>
#include <uk/utils/safe/safe_alloc.h>

static uk_utils_logger *uk_utils_global_log = NULL;

bool uk_utils_logger_manager_init() {
    uk_utils_global_log = uk_utils_logger_create();
    uk_utils_logger_set_details(uk_utils_global_log, false);
    return true;
}

void uk_utils_logger_manager_uninit() {
    uk_utils_logger_destroy(uk_utils_global_log);
}

uk_utils_logger *uk_utils_logger_manager_get_logger() {
    return uk_utils_global_log;
}
