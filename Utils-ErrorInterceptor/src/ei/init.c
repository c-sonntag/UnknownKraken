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

#include <ei/init.h>
#include <ei/thread/thread_storage.h>
#include <ei/bool.h>
#include <ei/logger/logger_manager.h>

static bool ei_thread_storage_initialized = false;

int ei_init() {
    if (!ei_thread_storage_initialized) {
        ei_thread_storage_initialized = ei_thread_storage_init();
    }

    ei_logger_manager_init();

    return ei_thread_storage_initialized;
}

void ei_uninit() {
    ei_logger_manager_uninit();

    if (ei_thread_storage_initialized) {
        ei_thread_storage_uninit();
    }
}
