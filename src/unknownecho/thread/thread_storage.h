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
 *  @file      thread_storage.h
 *  @brief     Singleton module to retreive an object per thread.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_THREAD_STORAGE_H
#define UNKNOWNECHO_THREAD_STORAGE_H

#include <unknownecho/bool.h>
#include <unknownecho/time/timer_struct.h>
#include <unknownecho/errorHandling/stacktrace_struct.h>

bool ue_thread_storage_init();

void ue_thread_storage_uninit();

bool ue_thread_storage_append_to_be_deleted_data(void *data);

ue_stacktrace *ue_thread_storage_get_stacktrace();

ue_stacktrace **ue_thread_storage_get_all_stacktrace(int *number);

ue_stacktrace *ue_thread_storage_get_stacktrace_from_thread_id(long ue_thread_id);

ue_timer *ue_thread_storage_get_timer();

ue_timer **ue_thread_storage_get_all_timer(int *number);

bool ue_thread_storage_set_char_data(char *data);

char *ue_thread_storage_get_char_data();

bool ue_thread_storage_set_int_data(int data);

int ue_thread_storage_get_int_data();

#endif
