/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoUtilsModule.										  *
 *																						  *
 *   LibUnknownEchoUtilsModule is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoUtilsModule is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoUtilsModule.  If not, see <http://www.gnu.org/licenses/>.   *
 ******************************************************************************************/

#include <ueum/container/string_vector.h>
#include <ueum/string/string_utility.h>
#include <ueum/alloc.h>
#include <ei/ei.h>

ueum_string_vector *ueum_string_vector_create_empty() {
    ueum_string_vector *vector;

    vector = NULL;

    ueum_safe_alloc(vector, ueum_string_vector, 1);

    vector->elements = NULL;
    vector->number = 0;

    return vector;
}

void ueum_string_vector_clean_up(ueum_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        ueum_safe_free(v->elements[i]);
    }
    ueum_safe_free(v->elements);
    v->number = 0;
}

void ueum_string_vector_destroy(ueum_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        ueum_safe_free(v->elements[i]);
    }
    ueum_safe_free(v->elements);

    ueum_safe_free(v);
}

bool ueum_string_vector_append(ueum_string_vector *v, const char *new_string) {
    int i;

    ei_check_parameter_or_return(v);

    if (!v->elements) {
        ueum_safe_alloc(v->elements, char *, 1);
        v->elements[0] = ueum_string_create_from(new_string);
        v->number++;
    } else {
        for (i = 0; i < v->number; i++) {
            if (!v->elements[i]) {
                v->elements[i] = ueum_string_create_from(new_string);
                return true;
            }
        }

        ueum_safe_realloc(v->elements, char *, v->number, 1);
        v->elements[v->number] = ueum_string_create_from(new_string);
        v->number++;
    }

    return true;
}

bool ueum_string_vector_append_vector(ueum_string_vector *from, ueum_string_vector *to) {
    int i;

    ei_check_parameter_or_return(from);
    ei_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        if (!ueum_string_vector_append(to, ueum_string_vector_get(from, i))) {
            return false;
        }
    }

    return true;
}

bool ueum_string_vector_remove(ueum_string_vector *v, int index) {
    if (!v) {
        return true;
    }

    if (!v->elements) {
        return true;
    }

    if (ueum_string_vector_size(v) < index) {
        ei_stacktrace_push_msg("Index out of range");
        return false;
    }

    ueum_safe_free(v->elements[index]);

    return true;
}

int ueum_string_vector_size(ueum_string_vector *v) {
    if (!v) {
        return -1;
    }

    if (!v->elements) {
        return -1;
    }

    return v->number;
}

char *ueum_string_vector_get(ueum_string_vector *v, int index) {
    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(v->elements);

    if (ueum_string_vector_size(v) < index) {
        ei_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return v->elements[index];
}

bool ueum_string_vector_is_empty(ueum_string_vector *v) {
    ei_check_parameter_or_return(v);

    return !v->elements || v->number <= 0;
}

bool ueum_string_vector_print(ueum_string_vector *v, FILE *out) {
    int i;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(out);

    if (ueum_string_vector_is_empty(v)) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        fprintf(out, "%s\n", v->elements[i]);
    }

    return true;
}

bool ueum_string_vector_contains(ueum_string_vector *v, char *target) {
    int i;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(target);

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
