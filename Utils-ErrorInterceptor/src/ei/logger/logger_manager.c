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

#include <ei/logger/logger_manager.h>
#include <ei/thread/thread_storage.h>
#include <ei/alloc.h>

static ei_logger *ei_global_log = NULL;

bool ei_logger_manager_init() {
    ei_global_log = ei_logger_create();
    ei_logger_set_details(ei_global_log, false);
    return true;
}

void ei_logger_manager_uninit() {
    ei_logger_destroy(ei_global_log);
}

ei_logger *ei_logger_manager_get_logger() {
    return ei_global_log;
}
