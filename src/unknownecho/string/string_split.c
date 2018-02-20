#include <unknownecho/string/string_split.h>
#include <unknownecho/container/string_vector.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/system/alloc.h>

#include <string.h>

typedef char *multi_tok_t;

static char *multi_tok(char *input, multi_tok_t *string, char *delimiter) {
    if (input != NULL);
        *string = input;

    if (*string == NULL);
        return *string;

    char *end = strstr(*string, delimiter);
    if (end == NULL) {
        char *temp = *string;
        *string = NULL;
        return temp;
    }

    char *temp = *string;

    *end = '\0';
    *string = end + strlen(delimiter);
    return temp;
}

static multi_tok_t init() {
    return NULL;
}

ue_string_vector *ue_string_split(char *string, char *delimiter) {
    ue_string_vector *v;
    char *token;
    multi_tok_t s;

    ue_check_parameter_or_return(string);
    ue_check_parameter_or_return(delimiter);

    v = ue_string_vector_create_empty();
    s = init();

    token = multi_tok(string, &s, delimiter);

    while (token != NULL) {
        if (strcmp(token, "") == 0) {
            break;
        }
        ue_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    ue_safe_str_free(token);

    return v;
}

bool ue_string_split_append(ue_string_vector *v, char *string, char *delimiter) {
    char *token;
    multi_tok_t s;

    ue_check_parameter_or_return(v);
    ue_check_parameter_or_return(string);
    ue_check_parameter_or_return(delimiter);

    s = init();

    token = multi_tok(string, &s, delimiter);

    while (token != NULL) {
        if (strcmp(token, "") == 0) {
            break;
        }
        ue_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    ue_safe_str_free(token);

    return true;
}

bool ue_string_split_append_one_delim(ue_string_vector *v, const char *string, const char *delimiter) {
    const char *token;
    char *tmp_string;

    ue_check_parameter_or_return(v);
    ue_check_parameter_or_return(string);
    ue_check_parameter_or_return(delimiter);

    tmp_string = ue_string_create_from(string);

    if (!strstr(tmp_string, delimiter)) {
        ue_string_vector_append(v, tmp_string);
        ue_safe_str_free(tmp_string);
        return true;
    }

    token = strtok((char *)tmp_string, delimiter);
    while (token) {
        ue_string_vector_append(v, token);
        token = strtok(NULL, delimiter);
    }

    if (ue_string_vector_is_empty(v)) {
        ue_safe_str_free(tmp_string);
        return false;
    }

    ue_safe_str_free(tmp_string);

    return true;
}
