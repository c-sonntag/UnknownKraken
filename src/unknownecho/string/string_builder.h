#ifndef UNKNOWNECHO_STRING_BUILDER_H
#define UNKNOWNECHO_STRING_BUILDER_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
    char *data;
    size_t max_size;
    size_t position;
} ue_string_builder;

ue_string_builder *ue_string_builder_create();

ue_string_builder *ue_string_builder_create_size(size_t max_size);

bool ue_string_builder_append(ue_string_builder *s, char *data, size_t data_len);

bool ue_string_builder_append_variadic(ue_string_builder *s, const char *format, ...);

void ue_string_builder_clean_up(ue_string_builder *s);

void ue_string_builder_destroy(ue_string_builder *s);

char *ue_string_builder_get_data(ue_string_builder *s);

size_t ue_string_builder_get_position(ue_string_builder *s);

#endif
