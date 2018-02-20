#ifndef UNKNOWNECHO_INTERNAL_ERROR_H
#define UNKNOWNECHO_INTERNAL_ERROR_H

#include <unknownecho/errorHandling/error.h>

#include <stdio.h>

typedef enum {
	UNKNOWNECHO_SUCCESS,
	UNKNOWNECHO_NO_SUCH_MEMORY,
	UNKNOWNECHO_FILE_NOT_FOUND,
    UNKNOWNECHO_INVALID_PARAMETER,
    UNKNOWNECHO_NO_INTERNET_CONNECTION,
	UNKNOWNECHO_UNKNOWN_ERROR
} ue_internal_error_type;

char *ue_internal_error_get_description(ue_internal_error_type type);

char *ue_internal_error_to_string(ue_error *e);

void ue_internal_error_print(ue_error *e, FILE *out);

#endif
