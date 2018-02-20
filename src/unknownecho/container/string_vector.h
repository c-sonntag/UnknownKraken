#ifndef UNKNOWNECHO_STRING_VECTOR_H
#define UNKNOWNECHO_STRING_VECTOR_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef struct {
    char **elements;
    int number;
} ue_string_vector;

ue_string_vector *ue_string_vector_create_empty();

void ue_string_vector_clean_up(ue_string_vector *v);

void ue_string_vector_destroy(ue_string_vector *v);

bool ue_string_vector_append(ue_string_vector *v, const char *new_string);

bool ue_string_vector_append_vector(ue_string_vector *from, ue_string_vector *to);

bool ue_string_vector_remove(ue_string_vector *v, int index);

int ue_string_vector_size(ue_string_vector *v);

char *ue_string_vector_get(ue_string_vector *v, int index);

bool ue_string_vector_is_empty(ue_string_vector *v);

bool ue_string_vector_print(ue_string_vector *v, FILE *out);

bool ue_string_vector_contains(ue_string_vector *v, char *target);

#endif
