#ifndef UNKNOWNECHO_STRING_SPLIT_H
#define UNKNOWNECHO_STRING_SPLIT_H

#include <unknownecho/bool.h>
#include <unknownecho/container/string_vector.h>

ue_string_vector *ue_string_split(char *string, char *delimiter);

bool ue_string_split_append(ue_string_vector *v, char *string, char *delimiter);

bool ue_string_split_append_one_delim(ue_string_vector *v, const char *string, const char *delimiter);

#endif
