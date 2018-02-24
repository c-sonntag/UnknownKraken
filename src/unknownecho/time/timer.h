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

/**
 *  @file      timer.h
 *  @brief     Portable and accurate way to measure the elapsed time
 *             between two parts in the code.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TIMER_H
#define UNKNOWNECHO_TIMER_H

#include <unknownecho/time/timer_struct.h>
#include <unknownecho/time/timer_measure_struct.h>
#include <unknownecho/time/timer_measure.h>
#include <unknownecho/time/clock_time_posix.h>
#include <unknownecho/bool.h>
#include <unknownecho/thread/thread_storage.h>

#include <time.h>

ue_timer *ue_timer_create_empty();

void ue_timer_destroy(ue_timer *tm);

bool ue_timer_start_impl(ue_timer *tm, unsigned int id, int timestamp);

bool ue_timer_stop_impl(ue_timer *tm, unsigned int id, int timestamp);

void ue_timer_average_impl(ue_timer *tm, unsigned int id, double *result);

bool ue_timer_average_print_impl(ue_timer *tm, unsigned int id, char *prefix_message);

void ue_timer_total_impl(ue_timer *tm, unsigned int id, double *result);

bool ue_timer_total_print_impl(ue_timer *tm, unsigned int id, char *prefix_message);

bool ue_timer_set_unity_impl(ue_timer *tm, unsigned int id, char *unity);

#define ue_timer_set_unity(id, unity) \
	ue_timer_set_unity_impl(ue_thread_storage_get_timer(), id, unity); \

#define ue_timer_start(id) \
	ue_timer_start_impl(ue_thread_storage_get_timer(), id, ue_get_posix_clock_time()); \

#define ue_timer_stop(id) \
	ue_timer_stop_impl(ue_thread_storage_get_timer(), id, ue_get_posix_clock_time()); \

#define ue_timer_average(id, result) \
	ue_timer_average_impl(ue_thread_storage_get_timer(), id, &result); \

#define ue_timer_average_print(id, message) \
	ue_timer_average_print_impl(ue_thread_storage_get_timer(), id, message); \

#define ue_timer_total(id, result) \
	ue_timer_total_impl(ue_thread_storage_get_timer(), id, &result); \

#define ue_timer_total_print(id, message) \
	ue_timer_total_print_impl(ue_thread_storage_get_timer(), id, message); \

#endif
