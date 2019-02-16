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

#include <ueum/time/timer_measure.h>
#include <ueum/safe/safe_alloc.h>
#include <ei/ei.h>
#include <ueum/string/string_utility.h>

#include <time.h>

static bool validate_unity(char *unity) {
    return unity &&
    (strcmp(unity, "ms") == 0 ||
    strcmp(unity, "us") == 0 ||
    strcmp(unity, "s") == 0);
}

ueum_timer_measure *ueum_timer_measure_create(unsigned int id) {
    ueum_timer_measure *measure;

    measure = NULL;

    ueum_safe_alloc(measure, ueum_timer_measure, 1);

    measure->id = id;
    measure->times_begin = NULL;
    measure->times_end = NULL;
    measure->times_begin_number = 0;
    measure->times_end_number = 0;
    measure->unity = ueum_string_create_from("ms");

    return measure;
}

void ueum_timer_measure_destroy(ueum_timer_measure *measure) {
    if (measure) {
        ueum_safe_free(measure->times_begin);
        ueum_safe_free(measure->times_end);
        ueum_safe_free(measure->unity);
        ueum_safe_free(measure);
    }
}

char *ueum_timer_measure_get_unity(ueum_timer_measure *measure) {
    return measure->unity;
}

bool ueum_timer_measure_set_unity(ueum_timer_measure *measure, char *unity) {
    if (measure && validate_unity(unity)) {
        measure->unity = unity;
        return true;
    }
    return false;
}

bool ueum_timer_measure_append_begin(ueum_timer_measure *measure, int time) {
    ueum_safe_realloc(measure->times_begin, int, measure->times_begin_number, 1);
    measure->times_begin[measure->times_begin_number] = time;
    measure->times_begin_number++;

    return true;
}

bool ueum_timer_measure_append_end(ueum_timer_measure *measure, int time) {
    ueum_safe_realloc(measure->times_end, int, measure->times_end_number, 1);
    measure->times_end[measure->times_end_number] = time;
    measure->times_end_number++;

    return true;
}

bool ueum_timer_measure_average(ueum_timer_measure *measure, double *result) {
    double sum;
    int i;

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
