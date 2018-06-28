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

#include <unknownecho/time/timer_measure.h>
#include <unknownecho/alloc.h>
#include <ei/ei.h>
#include <unknownecho/string/string_utility.h>

#include <time.h>

static bool validate_unity(char *unity) {
	return unity &&
		(strcmp(unity, "ms") == 0 ||
		strcmp(unity, "us") == 0 ||
		strcmp(unity, "s") == 0);
}

ue_timer_measure *ue_timer_measure_create(unsigned int id) {
	ue_timer_measure *measure;

	ue_safe_alloc(measure, ue_timer_measure, 1);

	measure->id = id;
	measure->times_begin = NULL;
	measure->times_end = NULL;
	measure->times_begin_number = 0;
	measure->times_end_number = 0;
	measure->unity = ue_string_create_from("ms");

	return measure;
}

void ue_timer_measure_destroy(ue_timer_measure *measure) {
	if (measure) {
		ue_safe_free(measure->times_begin);
		ue_safe_free(measure->times_end);
		ue_safe_free(measure->unity);
		ue_safe_free(measure);
	}
}

char *ue_timer_measure_get_unity(ue_timer_measure *measure) {
	return measure->unity;
}

bool ue_timer_measure_set_unity(ue_timer_measure *measure, char *unity) {
	if (measure && validate_unity(unity)) {
		measure->unity = unity;
		return true;
	}
	return false;
}

bool ue_timer_measure_append_begin(ue_timer_measure *measure, int time) {
	ue_safe_realloc(measure->times_begin, int, measure->times_begin_number, 1);
	measure->times_begin[measure->times_begin_number] = time;
	measure->times_begin_number++;

	return true;
}

bool ue_timer_measure_append_end(ue_timer_measure *measure, int time) {
	ue_safe_realloc(measure->times_end, int, measure->times_end_number, 1);
	measure->times_end[measure->times_end_number] = time;
	measure->times_end_number++;

	return true;
}

bool ue_timer_measure_average(ue_timer_measure *measure, double *result) {
	double sum;
	unsigned int i;

	sum = 0.0;
	*result = 0.0;

	if (measure->times_begin_number < measure->times_end_number) {
		ei_stacktrace_push_msg("There's less times start than times end");
		return false;
	}
	else if (measure->times_begin_number > measure->times_end_number) {
		ei_stacktrace_push_msg("There's more times start than times end");
		return false;
	} else if (measure->times_begin_number == 0 && measure->times_end_number == 0) {
		ei_stacktrace_push_msg("Couple of times are equals to 0");
		return false;
	}

	for (i = 0; i < measure->times_begin_number; i++) {
		sum += (double)(measure->times_end[i] - measure->times_begin[i]);
	}

	*result = (double)(sum / measure->times_begin_number);

	return true;
}
