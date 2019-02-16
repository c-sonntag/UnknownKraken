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

#ifndef UNKNOWNECHOUTILSMODULE_TIMER_H
#define UNKNOWNECHOUTILSMODULE_TIMER_H

#include <ueum/time/timer_struct.h>
#include <ueum/time/timer_measure_struct.h>
#include <ueum/time/timer_measure.h>
#include <ueum/time/real_current_time.h>
#include <ueum/compiler/bool.h>

#include <time.h>

ueum_timer *ueum_timer_create_empty();

void ueum_timer_destroy(ueum_timer *tm);

bool ueum_timer_start_impl(ueum_timer *tm, unsigned int id, int timestamp);

bool ueum_timer_stop_impl(ueum_timer *tm, unsigned int id, int timestamp);

void ueum_timer_average_impl(ueum_timer *tm, unsigned int id, double *result);

bool ueum_timer_average_print_impl(ueum_timer *tm, unsigned int id, char *prefix_message);

void ueum_timer_total_impl(ueum_timer *tm, unsigned int id, double *result);

bool ueum_timer_total_print_impl(ueum_timer *tm, unsigned int id, char *prefix_message);

bool ueum_timer_set_unity_impl(ueum_timer *tm, unsigned int id, char *unity);

/**
 * Replace thread storage by libuv uv_key API
 */

/*#define ueum_timer_set_unity(id, unity) \
    ueum_timer_set_unity_impl(ueum_thread_storage_get_timer(), id, unity); \

#define ueum_timer_start(id) \
    ueum_timer_start_impl(ueum_thread_storage_get_timer(), id, ueum_get_real_current_time()); \

#define ueum_timer_stop(id) \
    ueum_timer_stop_impl(ueum_thread_storage_get_timer(), id, ueum_get_real_current_time()); \

#define ueum_timer_average(id, result) \
    ueum_timer_average_impl(ueum_thread_storage_get_timer(), id, &result); \

#define ueum_timer_average_print(id, message) \
    ueum_timer_average_print_impl(ueum_thread_storage_get_timer(), id, message); \

#define ueum_timer_total(id, result) \
    ueum_timer_total_impl(ueum_thread_storage_get_timer(), id, &result); \

#define ueum_timer_total_print(id, message) \
    ueum_timer_total_print_impl(ueum_thread_storage_get_timer(), id, message); \*/

#endif
