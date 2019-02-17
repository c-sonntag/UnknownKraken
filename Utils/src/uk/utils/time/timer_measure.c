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

#include <uk/utils/time/timer_measure.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>
#include <uk/utils/string/string_utility.h>

#include <time.h>

static bool validate_unity(char *unity) {
    return unity &&
    (strcmp(unity, "ms") == 0 ||
    strcmp(unity, "us") == 0 ||
    strcmp(unity, "s") == 0);
}

uk_utils_timer_measure *uk_utils_timer_measure_create(unsigned int id) {
    uk_utils_timer_measure *measure;

    measure = NULL;

    uk_utils_safe_alloc(measure, uk_utils_timer_measure, 1);

    measure->id = id;
    measure->times_begin = NULL;
    measure->times_end = NULL;
    measure->times_begin_number = 0;
    measure->times_end_number = 0;
    measure->unity = uk_utils_string_create_from("ms");

    return measure;
}

void uk_utils_timer_measure_destroy(uk_utils_timer_measure *measure) {
    if (measure) {
        uk_utils_safe_free(measure->times_begin);
        uk_utils_safe_free(measure->times_end);
        uk_utils_safe_free(measure->unity);
        uk_utils_safe_free(measure);
    }
}

char *uk_utils_timer_measure_get_unity(uk_utils_timer_measure *measure) {
    return measure->unity;
}

bool uk_utils_timer_measure_set_unity(uk_utils_timer_measure *measure, char *unity) {
    if (measure && validate_unity(unity)) {
        measure->unity = unity;
        return true;
    }
    return false;
}

bool uk_utils_timer_measure_append_begin(uk_utils_timer_measure *measure, int time) {
    uk_utils_safe_realloc(measure->times_begin, int, measure->times_begin_number, 1);
    measure->times_begin[measure->times_begin_number] = time;
    measure->times_begin_number++;

    return true;
}

bool uk_utils_timer_measure_append_end(uk_utils_timer_measure *measure, int time) {
    uk_utils_safe_realloc(measure->times_end, int, measure->times_end_number, 1);
    measure->times_end[measure->times_end_number] = time;
    measure->times_end_number++;

    return true;
}

bool uk_utils_timer_measure_average(uk_utils_timer_measure *measure, double *result) {
    double sum;
    int i;

    sum = 0.0;
    *result = 0.0;

    if (measure->times_begin_number < measure->times_end_number) {
        uk_utils_stacktrace_push_msg("There's less times start than times end");
        return false;
    }
    else if (measure->times_begin_number > measure->times_end_number) {
        uk_utils_stacktrace_push_msg("There's more times start than times end");
        return false;
    } else if (measure->times_begin_number == 0 && measure->times_end_number == 0) {
        uk_utils_stacktrace_push_msg("Couple of times are equals to 0");
        return false;
    }

    for (i = 0; i < measure->times_begin_number; i++) {
        sum += (double)(measure->times_end[i] - measure->times_begin[i]);
    }

    *result = (double)(sum / measure->times_begin_number);

    return true;
}
