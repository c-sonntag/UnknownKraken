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

#include <ueum/time/timer.h>
#include <ueum/time/timer_measure.h>
#include <ueum/safe/safe_alloc.h>
#include <ueum/string/string_utility.h>

#include <string.h>

static ueum_timer_measure *get_timer_measure_from_id(ueum_timer *tm, unsigned int id) {
    ueum_timer_measure *measure;
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
            ueum_safe_realloc(tm->measures, ueum_timer_measure *, tm->measures_number, 1);
            tm->measures[tm->measures_number] = ueum_timer_measure_create(id);
            measure = tm->measures[tm->measures_number];
            tm->measures_number++;
        }
    }
    else {
        ueum_safe_alloc(tm->measures, ueum_timer_measure *, 1);
        tm->measures[tm->measures_number] = ueum_timer_measure_create(id);
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

ueum_timer *ueum_timer_create_empty() {
    ueum_timer *tm;

    tm = NULL;

    ueum_safe_alloc(tm, ueum_timer, 1);
    tm->measures = NULL;
    tm->measures_number = 0;
    tm->ueum_thread_id = -1;

    return tm;
}

void ueum_timer_destroy(ueum_timer *tm) {
    unsigned int i;

    if (tm) {
        if (tm->measures) {
            for (i = 0; i < tm->measures_number; i++) {
                ueum_timer_measure_destroy(tm->measures[i]);
            }
            ueum_safe_free(tm->measures);
        }
        ueum_safe_free(tm);
    }
}

bool ueum_timer_set_unity_impl(ueum_timer *tm, unsigned int id, char *unity) {
    ueum_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return ueum_timer_measure_set_unity(measure, unity);
}

bool ueum_timer_start_impl(ueum_timer *tm, unsigned int id, int timestamp) {
    ueum_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return ueum_timer_measure_append_begin(measure, timestamp);
}

bool ueum_timer_stop_impl(ueum_timer *tm, unsigned int id, int timestamp) {
    ueum_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    return ueum_timer_measure_append_end(measure, timestamp);
}

void ueum_timer_average_impl(ueum_timer *tm, unsigned int id, double *result) {
    ueum_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    ueum_timer_measure_average(measure, result);
}

bool ueum_timer_average_print_impl(ueum_timer *tm, unsigned int id, char *prefix_message) {
    (void)tm;
    (void)id;
    (void)prefix_message;
    /*double result;
    ueum_timer_measure *measure;
    char *unity;

    result = 0.0;
    measure = get_timer_measure_from_id(tm, id);
    unity = ueum_timer_measure_get_unity(measure);

    ueum_timer_average(id, result);

    printf("Average time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

    return true;*/

    ei_stacktrace_push_msg("Not implemented");
    return false;
}

void ueum_timer_total_impl(ueum_timer *tm, unsigned int id, double *result) {
    int i;
    ueum_timer_measure *measure;

    measure = get_timer_measure_from_id(tm, id);

    *result = 0;

    for (i = 0; i < measure->times_end_number; i++) {
        *result += (measure->times_end[i] - measure->times_begin[i]);
    }
}

bool ueum_timer_total_print_impl(ueum_timer *tm, unsigned int id, char *prefix_message) {
    (void)tm;
    (void)id;
    (void)prefix_message;
    /*double result;
    ueum_timer_measure *measure;
    char *unity;

    result = 0.0;
    measure = get_timer_measure_from_id(tm, id);
    unity = ueum_timer_measure_get_unity(measure);

    ueum_timer_total(id, result);

    printf("Total time for %s : %.4f%s\n", prefix_message, resolve_result_unity(unity, result), unity);

    return true;*/

    ei_stacktrace_push_msg("Not implemented");
    return false;
}
