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

#ifndef UNKNOWNECHOUTILSMODULE_TIMER_MEASURE_H
#define UNKNOWNECHOUTILSMODULE_TIMER_MEASURE_H

#include <ueum/time/timer_measure_struct.h>
#include <ueum/compiler/bool.h>

ueum_timer_measure *ueum_timer_measure_create(unsigned int id);

void ueum_timer_measure_destroy(ueum_timer_measure *measure);

char *ueum_timer_measure_get_unity(ueum_timer_measure *measure);

bool ueum_timer_measure_set_unity(ueum_timer_measure *measure, char *unity);

bool ueum_timer_measure_append_begin(ueum_timer_measure *measure, int time);

bool ueum_timer_measure_append_end(ueum_timer_measure *measure, int time);

bool ueum_timer_measure_average(ueum_timer_measure *measure, double *result);

#endif
