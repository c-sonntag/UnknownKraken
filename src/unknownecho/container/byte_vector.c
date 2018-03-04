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

#include <unknownecho/container/byte_vector.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

#include <string.h>

static ue_byte_vector_element *new_element(unsigned char *data, size_t size) {
    ue_byte_vector_element *element;

    ue_safe_alloc(element, ue_byte_vector_element, 1);
    element->data = data;
    element->size = size;

    return element;
}

ue_byte_vector *ue_byte_vector_create_empty() {
    ue_byte_vector *vector;

    ue_safe_alloc(vector, ue_byte_vector, 1);

    vector->elements = NULL;
    vector->number = 0;

    return vector;
}

void ue_byte_vector_clean_up(ue_byte_vector *vector) {
    int i;

    if (!vector) {
        return;
    }

    for (i = 0; i < vector->number; i++) {
        if (vector->elements[i]) {
            ue_safe_free(vector->elements[i]->data);
            ue_safe_free(vector->elements[i]);
        }
    }
    ue_safe_free(vector->elements);
    vector->number = 0;
}

void ue_byte_vector_destroy(ue_byte_vector *vector) {
    int i;

    if (!vector) {
        return;
    }

    if (vector->elements) {
        for (i = 0; i < vector->number; i++) {
            if (vector->elements[i]) {
                ue_safe_free(vector->elements[i]->data);
                ue_safe_free(vector->elements[i]);
            }
        }
        ue_safe_free(vector->elements);
    }

    ue_safe_free(vector);
}

bool ue_byte_vector_append_string(ue_byte_vector *vector, const char *new_string) {
    int i;

    ue_check_parameter_or_return(vector);

    if (!vector->elements) {
        ue_safe_alloc(vector->elements, ue_byte_vector_element *, 1);
        vector->elements[0] = new_element(ue_bytes_create_from_string(new_string), strlen(new_string));
        vector->number++;
    } else {
        for (i = 0; i < vector->number; i++) {
            if (!vector->elements[i]) {
                vector->elements[i] = new_element(ue_bytes_create_from_string(new_string), strlen(new_string));
                return true;
            }
        }

        ue_safe_realloc(vector->elements, ue_byte_vector_element *, vector->number, 1);
        vector->elements[vector->number] = new_element(ue_bytes_create_from_string(new_string), strlen(new_string));
        vector->number++;
    }

    return true;
}

bool ue_byte_vector_append_bytes(ue_byte_vector *vector, unsigned char *new_bytes, size_t new_bytes_size) {
    int i;

    ue_check_parameter_or_return(vector);

    if (!vector->elements) {
        ue_safe_alloc(vector->elements, ue_byte_vector_element *, 1);
        vector->elements[0] = new_element(ue_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
        vector->number++;
    } else {
        for (i = 0; i < vector->number; i++) {
            if (!vector->elements[i]) {
                vector->elements[i] = new_element(ue_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
                return true;
            }
        }

        ue_safe_realloc(vector->elements, ue_byte_vector_element *, vector->number, 1);
        vector->elements[vector->number] = new_element(ue_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
        vector->number++;
    }

    return true;
}

bool ue_byte_vector_append_vector(ue_byte_vector *from, ue_byte_vector *to) {
    int i;
    ue_byte_vector_element *current_element;

    ue_check_parameter_or_return(from);
    ue_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        current_element = ue_byte_vector_get(from, i);
        if (!ue_byte_vector_append_bytes(to, current_element->data, current_element->size)) {
            return false;
        }
    }

    return true;
}

bool ue_byte_vector_remove(ue_byte_vector *vector, int index) {
    if (!vector) {
        return true;
    }

    if (!vector->elements) {
        return true;
    }

    if (ue_byte_vector_size(vector) < index) {
        ue_stacktrace_push_msg("Index out of range");
        return false;
    }

    ue_safe_free(vector->elements[index]);

    return true;
}

int ue_byte_vector_size(ue_byte_vector *vector) {
    if (!vector) {
        return -1;
    }

    if (!vector->elements) {
        return -1;
    }

    return vector->number;
}

ue_byte_vector_element *ue_byte_vector_get(ue_byte_vector *vector, int index) {
    ue_check_parameter_or_return(vector);
    ue_check_parameter_or_return(vector->elements);

    if (ue_byte_vector_size(vector) < index) {
        ue_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return vector->elements[index];
}

bool ue_byte_vector_is_empty(ue_byte_vector *vector) {
    ue_check_parameter_or_return(vector);

    return !vector->elements || vector->number <= 0;
}

bool ue_byte_vector_print(ue_byte_vector *vector, FILE *out) {
    int i;
    size_t j;

    ue_check_parameter_or_return(vector);
    ue_check_parameter_or_return(out);

    if (ue_byte_vector_is_empty(vector)) {
        return false;
    }

    for (i = 0; i < vector->number; i++) {
        for (j = 0; j < vector->elements[i]->size; j++) {
            fprintf(out, "%c", vector->elements[i]->data[j]);
        }
        fprintf(out, "\n");
    }

    return true;
}

bool ue_byte_vector_print_element(ue_byte_vector *vector, int index, FILE *out) {
    ue_byte_vector_element *element;
    size_t i;

    if (!(element = ue_byte_vector_get(vector, index))) {
        ue_stacktrace_push_msg("Failed to found element at index %d", index);
        return false;
    }

    for (i = 0; i < element->size; i++) {
        fprintf(out, "%c", element->data[i]);
    }
    fprintf(out, "\n");

    return true;
}

bool ue_byte_vector_contains(ue_byte_vector *vector, unsigned char *target, size_t target_size) {
    int i;

    ue_check_parameter_or_return(vector);
    ue_check_parameter_or_return(target);

    if (vector->number == 0) {
        return false;
    }

    for (i = 0; i < vector->number; i++) {
        if (vector->elements[i] && memcmp(vector->elements[i]->data, target, target_size) == 0) {
            return true;
        }
    }

    return false;
}

bool ue_byte_vector_element_print_string(ue_byte_vector_element *element, FILE *out) {
    size_t i;

    ue_check_parameter_or_return(element);
    ue_check_parameter_or_return(element->data);
    ue_check_parameter_or_return(element->size);
    ue_check_parameter_or_return(out);

    for (i = 0; i < element->size; i++) {
        fprintf(out, "%c", element->data[i]);
    }
    fprintf(out, "\n");

    return true;
}
