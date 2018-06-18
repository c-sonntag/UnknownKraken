/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/string/string_split.h>
#include <uecm/container/string_vector.h>
#include <uecm/string/string_utility.h>
#include <ei/ei.h>
#include <uecm/alloc.h>

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

uecm_string_vector *uecm_string_split(const char *string, const char *delimiter) {
    uecm_string_vector *v;
    char *token, *input;
    multi_tok_t s;

    ei_check_parameter_or_return(string);
    ei_check_parameter_or_return(delimiter);

    v = uecm_string_vector_create_empty();
    s = init();
    input = uecm_string_create_from(string);

    token = multi_tok(input, &s, delimiter);

    while (token != NULL) {
        if (strcmp(token, "") == 0) {
            break;
        }
        uecm_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    uecm_safe_str_free(token);
    uecm_safe_str_free(input);

    return v;
}

bool uecm_string_split_append(uecm_string_vector *v, char *string, char *delimiter) {
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
        uecm_string_vector_append(v, token);
        token = multi_tok(NULL, &s, delimiter);
    }
    uecm_safe_str_free(token);

    return true;
}

bool uecm_string_split_append_one_delim(uecm_string_vector *v, const char *string, const char *delimiter) {
    const char *token;
    char *tmp_string;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(string);
    ei_check_parameter_or_return(delimiter);

    tmp_string = uecm_string_create_from(string);

    if (!strstr(tmp_string, delimiter)) {
        uecm_string_vector_append(v, tmp_string);
        uecm_safe_str_free(tmp_string);
        return true;
    }

    token = strtok((char *)tmp_string, delimiter);
    while (token) {
        uecm_string_vector_append(v, token);
        token = strtok(NULL, delimiter);
    }

    if (uecm_string_vector_is_empty(v)) {
        uecm_safe_str_free(tmp_string);
        return false;
    }

    uecm_safe_str_free(tmp_string);

    return true;
}
