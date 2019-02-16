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

#include <ueum/string/string_split.h>
#include <ueum/container/string_vector.h>
#include <ueum/string/string_utility.h>
#include <ei/ei.h>
#include <ueum/safe/safe_alloc.h>

#include <string.h>

typedef char *multi_tok_t;

static char *multi_tok(char *input, multi_tok_t *string, const char *delimiter) {
    if (input != NULL) {
        *string = input;
    }

    if (*string == NULL) {
        return *string;
    }

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

ueum_string_vector *ueum_string_split(const char *string, const char *delimiter) {
    ueum_string_vector *v;
    char *token, *input;
    multi_tok_t s;

    ei_check_parameter_or_return(string);
    ei_check_parameter_or_return(delimiter);

    v = ueum_string_vector_create_empty();
    s = init();
    input = ueum_string_create_from(string);

    token = multi_tok(input, &s, delimiter);

    while (token != NULL) {
        if (strcmp(token, "") == 0) {
            break;
        }
        ueum_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    ueum_safe_str_free(token);
    ueum_safe_str_free(input);

    return v;
}

bool ueum_string_split_append(ueum_string_vector *v, char *string, char *delimiter) {
    char *token;
    multi_tok_t s;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(string);
    ei_check_parameter_or_return(delimiter);

    s = init();

    token = multi_tok(string, &s, delimiter);

    while (token != NULL) {
        if (strcmp(token, "") == 0) {
            break;
        }
        ueum_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    ueum_safe_str_free(token);

    return true;
}

bool ueum_string_split_append_one_delim(ueum_string_vector *v, const char *string, const char *delimiter) {
    const char *token;
    char *tmp_string;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(string);
    ei_check_parameter_or_return(delimiter);

    tmp_string = ueum_string_create_from(string);

    if (!strstr(tmp_string, delimiter)) {
        ueum_string_vector_append(v, tmp_string);
        ueum_safe_str_free(tmp_string);
        return true;
    }

    token = strtok((char *)tmp_string, delimiter);
    while (token) {
        ueum_string_vector_append(v, token);
        token = strtok(NULL, delimiter);
    }

    if (ueum_string_vector_is_empty(v)) {
        ueum_safe_str_free(tmp_string);
        return false;
    }

    ueum_safe_str_free(tmp_string);

    return true;
}
