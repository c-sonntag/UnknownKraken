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

#include <uk/utils/container/string_vector.h>
#include <uk/utils/string/string_utility.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

uk_utils_string_vector *uk_utils_string_vector_create_empty() {
    uk_utils_string_vector *vector;

    vector = NULL;

    uk_utils_safe_alloc(vector, uk_utils_string_vector, 1);

    vector->elements = NULL;
    vector->number = 0;

    return vector;
}

void uk_utils_string_vector_clean_up(uk_utils_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        uk_utils_safe_free(v->elements[i]);
    }
    uk_utils_safe_free(v->elements);
    v->number = 0;
}

void uk_utils_string_vector_destroy(uk_utils_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        uk_utils_safe_free(v->elements[i]);
    }
    uk_utils_safe_free(v->elements);

    uk_utils_safe_free(v);
}

bool uk_utils_string_vector_append(uk_utils_string_vector *v, const char *new_string) {
    int i;

    uk_utils_check_parameter_or_return(v);

    if (!v->elements) {
        uk_utils_safe_alloc(v->elements, char *, 1);
        v->elements[0] = uk_utils_string_create_from(new_string);
        v->number++;
    } else {
        for (i = 0; i < v->number; i++) {
            if (!v->elements[i]) {
                v->elements[i] = uk_utils_string_create_from(new_string);
                return true;
            }
        }

        uk_utils_safe_realloc(v->elements, char *, v->number, 1);
        v->elements[v->number] = uk_utils_string_create_from(new_string);
        v->number++;
    }

    return true;
}

bool uk_utils_string_vector_append_vector(uk_utils_string_vector *from, uk_utils_string_vector *to) {
    int i;

    uk_utils_check_parameter_or_return(from);
    uk_utils_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        if (!uk_utils_string_vector_append(to, uk_utils_string_vector_get(from, i))) {
            return false;
        }
    }

    return true;
}

bool uk_utils_string_vector_remove(uk_utils_string_vector *v, int index) {
    if (!v) {
        return true;
    }

    if (!v->elements) {
        return true;
    }

    if (uk_utils_string_vector_size(v) < index) {
        uk_utils_stacktrace_push_msg("Index out of range");
        return false;
    }

    uk_utils_safe_free(v->elements[index]);

    return true;
}

int uk_utils_string_vector_size(uk_utils_string_vector *v) {
    if (!v) {
        return -1;
    }

    if (!v->elements) {
        return -1;
    }

    return v->number;
}

char *uk_utils_string_vector_get(uk_utils_string_vector *v, int index) {
    uk_utils_check_parameter_or_return(v);
    uk_utils_check_parameter_or_return(v->elements);

    if (uk_utils_string_vector_size(v) < index) {
        uk_utils_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return v->elements[index];
}

bool uk_utils_string_vector_is_empty(uk_utils_string_vector *v) {
    uk_utils_check_parameter_or_return(v);

    return !v->elements || v->number <= 0;
}

bool uk_utils_string_vector_print(uk_utils_string_vector *v, FILE *out) {
    int i;

    uk_utils_check_parameter_or_return(v);
    uk_utils_check_parameter_or_return(out);

    if (uk_utils_string_vector_is_empty(v)) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        fprintf(out, "%s\n", v->elements[i]);
    }

    return true;
}

bool uk_utils_string_vector_contains(uk_utils_string_vector *v, char *target) {
    int i;

    uk_utils_check_parameter_or_return(v);
    uk_utils_check_parameter_or_return(target);

    if (v->number == 0) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        if (strcmp(v->elements[i], target) == 0) {
            return true;
        }
    }

    return false;
}
