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

#ifndef UnknownKrakenUtils_TIMER_MEASURE_H
#define UnknownKrakenUtils_TIMER_MEASURE_H

#include <uk/utils/time/timer_measure_struct.h>
#include <uk/utils/compiler/bool.h>

uk_utils_timer_measure *uk_utils_timer_measure_create(unsigned int id);

void uk_utils_timer_measure_destroy(uk_utils_timer_measure *measure);

char *uk_utils_timer_measure_get_unity(uk_utils_timer_measure *measure);

bool uk_utils_timer_measure_set_unity(uk_utils_timer_measure *measure, char *unity);

bool uk_utils_timer_measure_append_begin(uk_utils_timer_measure *measure, int time);

bool uk_utils_timer_measure_append_end(uk_utils_timer_measure *measure, int time);

bool uk_utils_timer_measure_average(uk_utils_timer_measure *measure, double *result);

#endif
