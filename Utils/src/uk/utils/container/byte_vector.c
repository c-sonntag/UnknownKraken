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

#include <uk/utils/container/byte_vector.h>
#include <uk/utils/byte/byte_utility.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

#include <string.h>

static uk_utils_byte_vector_element *new_element(unsigned char *data, size_t size) {
    uk_utils_byte_vector_element *element;

    element = NULL;

    uk_utils_safe_alloc(element, uk_utils_byte_vector_element, 1);
    element->data = data;
    element->size = size;

    return element;
}

uk_utils_byte_vector *uk_utils_byte_vector_create_empty() {
    uk_utils_byte_vector *vector;

    vector = NULL;

    uk_utils_safe_alloc(vector, uk_utils_byte_vector, 1);

    vector->elements = NULL;
    vector->number = 0;

    return vector;
}

void uk_utils_byte_vector_clean_up(uk_utils_byte_vector *vector) {
    int i;

    if (!vector) {
        return;
    }

    for (i = 0; i < vector->number; i++) {
        if (vector->elements[i]) {
            uk_utils_safe_free(vector->elements[i]->data);
            uk_utils_safe_free(vector->elements[i]);
        }
    }
    uk_utils_safe_free(vector->elements);
    vector->number = 0;
}

void uk_utils_byte_vector_destroy(uk_utils_byte_vector *vector) {
    int i;

    if (!vector) {
        return;
    }

    if (vector->elements) {
        for (i = 0; i < vector->number; i++) {
            if (vector->elements[i]) {
                uk_utils_safe_free(vector->elements[i]->data);
                uk_utils_safe_free(vector->elements[i]);
            }
        }
        uk_utils_safe_free(vector->elements);
    }

    uk_utils_safe_free(vector);
}

bool uk_utils_byte_vector_append_string(uk_utils_byte_vector *vector, const char *new_string) {
    int i;

    uk_utils_check_parameter_or_return(vector);

    if (!vector->elements) {
        uk_utils_safe_alloc(vector->elements, uk_utils_byte_vector_element *, 1);
        vector->elements[0] = new_element(uk_utils_bytes_create_from_string(new_string), strlen(new_string));
        vector->number++;
    } else {
        for (i = 0; i < vector->number; i++) {
            if (!vector->elements[i]) {
                vector->elements[i] = new_element(uk_utils_bytes_create_from_string(new_string), strlen(new_string));
                return true;
            }
        }

        uk_utils_safe_realloc(vector->elements, uk_utils_byte_vector_element *, vector->number, 1);
        vector->elements[vector->number] = new_element(uk_utils_bytes_create_from_string(new_string), strlen(new_string));
        vector->number++;
    }

    return true;
}

bool uk_utils_byte_vector_append_bytes(uk_utils_byte_vector *vector, unsigned char *new_bytes, size_t new_bytes_size) {
    int i;

    uk_utils_check_parameter_or_return(vector);

    if (!vector->elements) {
        uk_utils_safe_alloc(vector->elements, uk_utils_byte_vector_element *, 1);
        vector->elements[0] = new_element(uk_utils_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
        vector->number++;
    } else {
        for (i = 0; i < vector->number; i++) {
            if (!vector->elements[i]) {
                vector->elements[i] = new_element(uk_utils_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
                return true;
            }
        }

        uk_utils_safe_realloc(vector->elements, uk_utils_byte_vector_element *, vector->number, 1);
        vector->elements[vector->number] = new_element(uk_utils_bytes_create_from_bytes(new_bytes, new_bytes_size), new_bytes_size);
        vector->number++;
    }

    return true;
}

bool uk_utils_byte_vector_append_vector(uk_utils_byte_vector *from, uk_utils_byte_vector *to) {
    int i;
    uk_utils_byte_vector_element *current_element;

    uk_utils_check_parameter_or_return(from);
    uk_utils_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        current_element = uk_utils_byte_vector_get(from, i);
        if (!uk_utils_byte_vector_append_bytes(to, current_element->data, current_element->size)) {
            return false;
        }
    }

    return true;
}

bool uk_utils_byte_vector_remove(uk_utils_byte_vector *vector, int index) {
    if (!vector) {
        return true;
    }

    if (!vector->elements) {
        return true;
    }

    if (uk_utils_byte_vector_size(vector) < index) {
        uk_utils_stacktrace_push_msg("Index out of range");
        return false;
    }

    uk_utils_safe_free(vector->elements[index]);

    return true;
}

int uk_utils_byte_vector_size(uk_utils_byte_vector *vector) {
    if (!vector) {
        return -1;
    }

    if (!vector->elements) {
        return -1;
    }

    return vector->number;
}

uk_utils_byte_vector_element *uk_utils_byte_vector_get(uk_utils_byte_vector *vector, int index) {
    uk_utils_check_parameter_or_return(vector);
    uk_utils_check_parameter_or_return(vector->elements);

    if (uk_utils_byte_vector_size(vector) < index) {
        uk_utils_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return vector->elements[index];
}

bool uk_utils_byte_vector_is_empty(uk_utils_byte_vector *vector) {
    uk_utils_check_parameter_or_return(vector);

    return !vector->elements || vector->number <= 0;
}

bool uk_utils_byte_vector_print(uk_utils_byte_vector *vector, FILE *out) {
    int i;
    size_t j;

    uk_utils_check_parameter_or_return(vector);
    uk_utils_check_parameter_or_return(out);

    if (uk_utils_byte_vector_is_empty(vector)) {
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

bool uk_utils_byte_vector_print_element(uk_utils_byte_vector *vector, int index, FILE *out) {
    uk_utils_byte_vector_element *element;
    size_t i;

    if ((element = uk_utils_byte_vector_get(vector, index)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to found element at index %d", index);
        return false;
    }

    for (i = 0; i < element->size; i++) {
        fprintf(out, "%c", element->data[i]);
    }
    fprintf(out, "\n");

    return true;
}

bool uk_utils_byte_vector_contains(uk_utils_byte_vector *vector, unsigned char *target, size_t target_size) {
    int i;

    uk_utils_check_parameter_or_return(vector);
    uk_utils_check_parameter_or_return(target);

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

bool uk_utils_byte_vector_element_print_string(uk_utils_byte_vector_element *element, FILE *out) {
    size_t i;

    uk_utils_check_parameter_or_return(element);
    uk_utils_check_parameter_or_return(element->data);
    uk_utils_check_parameter_or_return(element->size);
    uk_utils_check_parameter_or_return(out);

    for (i = 0; i < element->size; i++) {
        fprintf(out, "%c", element->data[i]);
    }
    fprintf(out, "\n");

    return true;
}
