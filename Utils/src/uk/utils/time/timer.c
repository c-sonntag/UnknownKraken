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

#include <uk/utils/time/timer.h>
#include <uk/utils/time/timer_measure.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/string/string_utility.h>

#include <string.h>

static uk_utils_timer_measure *get_timer_measure_from_id(uk_utils_timer *tm, unsigned int id) {
    uk_utils_timer_measure *measure;
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
            uk_utils_safe_realloc(tm->measures, uk_utils_timer_measure *, tm->measures_number, 1);
            tm->measures[tm->measures_number] = uk_utils_timer_measure_create(id);
            measure = tm->measures[tm->measures_number];
            tm->measures_number++;
        }
    }
    else {
        uk_utils_safe_alloc(tm->measures, uk_utils_timer_measure *, 1);
        tm->measures[tm->measures_number] = uk_utils_timer_measure_create(id);
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
        uk_utils_logger_warn("Unknown unity '%s', returned unchanged value", unity);
        result = n;
    }

    return result;
}

uk_utils_timer *uk_utils_timer_create_empty() {
    uk_utils_timer *tm;

    tm = NULL;

    uk_utils_safe_alloc(tm, uk_utils_timer, 1);
    tm->measures = NULL;
    tm->measures_number = 0;
    tm->uk_utils_thread_id = -1;

    return tm;
}

void uk_utils_timer_destroy(uk_utils_timer *tm) {
    unsigned int i;

    if (tm) {
        if (tm->measures) {
            for (i = 0; i < tm->measures_number; i++) {
                uk_utils_timer_measure_destroy(tm->measures[i]);
            }
            uk_utils_safe_free(tm->measures);
        }
        uk_utils_safe_free(tm);
    }
}

bool uk_utils_timer_set_unity_impl(uk_utils_timer *tm, unsigned int id, char *unity) {
    uk_utils_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return uk_utils_timer_measure_set_unity(measure, unity);
}

bool uk_utils_timer_start_impl(uk_utils_timer *tm, unsigned int id, int timestamp) {
    uk_utils_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return uk_utils_timer_measure_append_begin(measure, timestamp);
}

bool uk_utils_timer_stop_impl(uk_utils_timer *tm, unsigned int id, int timestamp) {
    uk_utils_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return uk_utils_timer_measure_append_end(measure, timestamp);
}

void uk_utils_timer_average_impl(uk_utils_timer *tm, unsigned int id, double *result) {
    uk_utils_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    uk_utils_timer_measure_average(measure, result);
}

bool uk_utils_timer_average_print_impl(uk_utils_timer *tm, unsigned int id, char *prefix_message) {
    (void)tm;
    (void)id;
    (void)prefix_message;
    /*double result;
    uk_utils_timer_measure *measure;
    char *unity;

    result = 0.0;
    measure = get_timer_measure_from_id(tm, id);
    unity = uk_utils_timer_measure_get_unity(measure);

    uk_utils_timer_average(id, result);

    printf("Average time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

    return true;*/

    uk_utils_stacktrace_push_msg("Not implemented");
    return false;
}

void uk_utils_timer_total_impl(uk_utils_timer *tm, unsigned int id, double *result) {
    int i;
    uk_utils_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    *result = 0;

    for (i = 0; i < measure->times_end_number; i++) {
        *result += (measure->times_end[i] - measure->times_begin[i]);
    }
}

bool uk_utils_timer_total_print_impl(uk_utils_timer *tm, unsigned int id, char *prefix_message) {
    (void)tm;
    (void)id;
    (void)prefix_message;
    /*double result;
    uk_utils_timer_measure *measure;
    char *unity;

    result = 0.0;
    measure = get_timer_measure_from_id(tm, id);
    unity = uk_utils_timer_measure_get_unity(measure);

    uk_utils_timer_total(id, result);

    printf("Total time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

    return true;*/

    uk_utils_stacktrace_push_msg("Not implemented");
    return false;
}
