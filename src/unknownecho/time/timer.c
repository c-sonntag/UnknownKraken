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

#include <unknownecho/time/timer.h>
#include <unknownecho/time/timer_measure.h>
#include <unknownecho/alloc.h>
#include <unknownecho/string/string_utility.h>

#include <string.h>

static ue_timer_measure *get_timer_measure_from_id(ue_timer *tm, unsigned int id) {
	ue_timer_measure *measure;
	unsigned int i;
	bool found;

	measure = NULL;
	found = false;

	if (tm->measures) {
		for (i = 0; i < tm->measures_number; i++) {
			if (tm->measures[i]->id == id) {
				measure = tm->measures[i];
				found = true;
				break;
			}
		}

		if (!found) {
			ue_safe_realloc(tm->measures, ue_timer_measure *, tm->measures_number, 1);
			tm->measures[tm->measures_number] = ue_timer_measure_create(id);
			measure = tm->measures[tm->measures_number];
			tm->measures_number++;
		}
	}
	else {
		ue_safe_alloc(tm->measures, ue_timer_measure *, 1);
		tm->measures[tm->measures_number] = ue_timer_measure_create(id);
		measure = tm->measures[tm->measures_number];
		tm->measures_number++;
	}

	return measure;
}

/*static */double resolve_result_unity(char *unity, double n) {
	double result;

	if (strcmp(unity, "us") == 0) {
		result = n;
	} else if (strcmp(unity, "ms") == 0) {
		result = n / 1000;
	} else if (strcmp(unity, "s") == 0) {
		result = n / 1000000;
	} else {
		ei_logger_warn("Unknown unity '%s', returned unchanged value", unity);
		result = n;
	}

	return result;
}

ue_timer *ue_timer_create_empty() {
	ue_timer *tm;

	ue_safe_alloc(tm, ue_timer, 1);
	tm->measures = NULL;
	tm->measures_number = 0;
	tm->ue_thread_id = -1;

	return tm;
}

void ue_timer_destroy(ue_timer *tm) {
	unsigned int i;

	if (tm) {
		if (tm->measures) {
			for (i = 0; i < tm->measures_number; i++) {
				ue_timer_measure_destroy(tm->measures[i]);
			}
			ue_safe_free(tm->measures);
		}
		ue_safe_free(tm);
	}
}

bool ue_timer_set_unity_impl(ue_timer *tm, unsigned int id, char *unity) {
	ue_timer_measure *measure;

	measure = get_timer_measure_from_id(tm, id);

	return ue_timer_measure_set_unity(measure, unity);
}

bool ue_timer_start_impl(ue_timer *tm, unsigned int id, int timestamp) {
	ue_timer_measure *measure;

	measure = get_timer_measure_from_id(tm, id);

	return ue_timer_measure_append_begin(measure, timestamp);
}

bool ue_timer_stop_impl(ue_timer *tm, unsigned int id, int timestamp) {
	ue_timer_measure *measure;

	measure = get_timer_measure_from_id(tm, id);

	return ue_timer_measure_append_end(measure, timestamp);
}

void ue_timer_average_impl(ue_timer *tm, unsigned int id, double *result) {
	ue_timer_measure *measure;

	measure = get_timer_measure_from_id(tm, id);

	ue_timer_measure_average(measure, result);
}

bool ue_timer_average_print_impl(ue_timer *tm, unsigned int id, char *prefix_message) {
	/*double result;
	ue_timer_measure *measure;
	char *unity;

	result = 0.0;
	measure = get_timer_measure_from_id(tm, id);
	unity = ue_timer_measure_get_unity(measure);

	ue_timer_average(id, result);

	printf("Average time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

	return true;*/

	ei_stacktrace_push_msg("Not implemented");
	return false;
}

void ue_timer_total_impl(ue_timer *tm, unsigned int id, double *result) {
	int i;
	ue_timer_measure *measure;

	measure = get_timer_measure_from_id(tm, id);

	*result = 0;

	for (i = 0; i < measure->times_end_number; i++) {
		*result += (measure->times_end[i] - measure->times_begin[i]);
	}
}

bool ue_timer_total_print_impl(ue_timer *tm, unsigned int id, char *prefix_message) {
	/*double result;
	ue_timer_measure *measure;
	char *unity;

	result = 0.0;
	measure = get_timer_measure_from_id(tm, id);
	unity = ue_timer_measure_get_unity(measure);

	ue_timer_total(id, result);

	printf("Total time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

	return true;*/

	ei_stacktrace_push_msg("Not implemented");
	return false;
}
