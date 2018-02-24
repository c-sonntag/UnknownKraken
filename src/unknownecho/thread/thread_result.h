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
 *  @file      thread_result.h
 *  @brief     Portable way of thread function result.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_THREAD_RESULT_H
#define UNKNOWNECHO_THREAD_RESULT_H

#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_thread_id *ti;
    void *result;
} ue_thread_result;

#define THREAD_RESULTS_MAX 10

ue_thread_result ue_thread_results[THREAD_RESULTS_MAX];

void ue_thread_results_init();

bool ue_thread_results_is_initialized();

bool ue_thread_result_exists(ue_thread_id *ti);

void ue_thread_result_add(ue_thread_id *ti);

void ue_thread_result_remove(ue_thread_id *ti);

void ue_thread_result_set(ue_thread_id *ti, void *result);

void *ue_thread_result_get(ue_thread_id *ti);

#endif
