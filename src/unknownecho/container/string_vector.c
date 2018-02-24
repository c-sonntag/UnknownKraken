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

#include <unknownecho/container/string_vector.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

ue_string_vector *ue_string_vector_create_empty() {
    ue_string_vector *v;

    ue_safe_alloc(v, ue_string_vector, 1);

    v->elements = NULL;
    v->number = 0;

    return v;
}

void ue_string_vector_clean_up(ue_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        ue_safe_free(v->elements[i]);
    }
    ue_safe_free(v->elements);
    v->number = 0;
}

void ue_string_vector_destroy(ue_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        ue_safe_free(v->elements[i]);
    }
    ue_safe_free(v->elements);

    ue_safe_free(v);
}

bool ue_string_vector_append(ue_string_vector *v, const char *new_string) {
    int i;

    ue_check_parameter_or_return(v);

    if (!v->elements) {
        ue_safe_alloc(v->elements, char *, 1);
        v->elements[0] = ue_string_create_from(new_string);
        v->number++;
    } else {
        for (i = 0; i < v->number; i++) {
            if (!v->elements[i]) {
                v->elements[i] = ue_string_create_from(new_string);
                return true;
            }
        }

        ue_safe_realloc(v->elements, char *, v->number, 1);
        v->elements[v->number] = ue_string_create_from(new_string);
        v->number++;
    }

    return true;
}

bool ue_string_vector_append_vector(ue_string_vector *from, ue_string_vector *to) {
    int i;

    ue_check_parameter_or_return(from);
    ue_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        if (!ue_string_vector_append(to, ue_string_vector_get(from, i))) {
            return false;
        }
    }

    return true;
}

bool ue_string_vector_remove(ue_string_vector *v, int index) {
    if (!v) {
        return true;
    }

    if (!v->elements) {
        return true;
    }

    if (ue_string_vector_size(v) < index) {
        ue_stacktrace_push_msg("Index out of range");
        return false;
    }

    ue_safe_free(v->elements[index]);

    return true;
}

int ue_string_vector_size(ue_string_vector *v) {
    if (!v) {
        return -1;
    }

    if (!v->elements) {
        return -1;
    }

    return v->number;
}

char *ue_string_vector_get(ue_string_vector *v, int index) {
    ue_check_parameter_or_return(v);
    ue_check_parameter_or_return(v->elements);

    if (ue_string_vector_size(v) < index) {
        ue_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return v->elements[index];
}

bool ue_string_vector_is_empty(ue_string_vector *v) {
    ue_check_parameter_or_return(v);

    return !v->elements || v->number <= 0;
}

bool ue_string_vector_print(ue_string_vector *v, FILE *out) {
    int i;

    ue_check_parameter_or_return(v);
    ue_check_parameter_or_return(out);

    if (ue_string_vector_is_empty(v)) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        fprintf(out, "%s\n", v->elements[i]);
    }

    return true;
}

bool ue_string_vector_contains(ue_string_vector *v, char *target) {
    int i;

    ue_check_parameter_or_return(v);
    ue_check_parameter_or_return(target);

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
