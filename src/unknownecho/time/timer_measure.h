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
 *  @file      timer_measure.h
 *  @brief     Module to manipulate timer_measure in order to measure time elapsed.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHO_TIMER_MEASURE_H
#define UNKNOWNECHO_TIMER_MEASURE_H

#include <unknownecho/time/timer_measure_struct.h>
#include <unknownecho/bool.h>

ue_timer_measure *ue_timer_measure_create(unsigned int id);

void ue_timer_measure_destroy(ue_timer_measure *measure);

char *ue_timer_measure_get_unity(ue_timer_measure *measure);

bool ue_timer_measure_set_unity(ue_timer_measure *measure, char *unity);

bool ue_timer_measure_append_begin(ue_timer_measure *measure, int time);

bool ue_timer_measure_append_end(ue_timer_measure *measure, int time);

bool ue_timer_measure_average(ue_timer_measure *measure, double *result);

#endif
