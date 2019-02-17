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

#ifndef UnknownKrakenUtils_TIMER_H
#define UnknownKrakenUtils_TIMER_H

#include <uk/utils/time/timer_struct.h>
#include <uk/utils/time/timer_measure_struct.h>
#include <uk/utils/time/timer_measure.h>
#include <uk/utils/time/real_current_time.h>
#include <uk/utils/compiler/bool.h>

#include <time.h>

uk_utils_timer *uk_utils_timer_create_empty();

void uk_utils_timer_destroy(uk_utils_timer *tm);

bool uk_utils_timer_start_impl(uk_utils_timer *tm, unsigned int id, int timestamp);

bool uk_utils_timer_stop_impl(uk_utils_timer *tm, unsigned int id, int timestamp);

void uk_utils_timer_average_impl(uk_utils_timer *tm, unsigned int id, double *result);

bool uk_utils_timer_average_print_impl(uk_utils_timer *tm, unsigned int id, char *prefix_message);

void uk_utils_timer_total_impl(uk_utils_timer *tm, unsigned int id, double *result);

bool uk_utils_timer_total_print_impl(uk_utils_timer *tm, unsigned int id, char *prefix_message);

bool uk_utils_timer_set_unity_impl(uk_utils_timer *tm, unsigned int id, char *unity);

/**
 * Replace thread storage by libuv uv_key API
 */

/*#define uk_utils_timer_set_unity(id, unity) \
    uk_utils_timer_set_unity_impl(uk_utils_thread_storage_get_timer(), id, unity); \

#define uk_utils_timer_start(id) \
    uk_utils_timer_start_impl(uk_utils_thread_storage_get_timer(), id, uk_utils_get_real_current_time()); \

#define uk_utils_timer_stop(id) \
    uk_utils_timer_stop_impl(uk_utils_thread_storage_get_timer(), id, uk_utils_get_real_current_time()); \

#define uk_utils_timer_average(id, result) \
    uk_utils_timer_average_impl(uk_utils_thread_storage_get_timer(), id, &result); \

#define uk_utils_timer_average_print(id, message) \
    uk_utils_timer_average_print_impl(uk_utils_thread_storage_get_timer(), id, message); \

#define uk_utils_timer_total(id, result) \
    uk_utils_timer_total_impl(uk_utils_thread_storage_get_timer(), id, &result); \

#define uk_utils_timer_total_print(id, message) \
    uk_utils_timer_total_print_impl(uk_utils_thread_storage_get_timer(), id, message); \*/

#endif
