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

#include <ueum/string/string_utility.h>
#include <ueum/string/string_builder.h>
#include <ueum/safe/safe_arithmetic.h>
#include <ei/ei.h>
#include <ueum/safe/safe_alloc.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h> /* for isspace(), toupper() */
#include <errno.h>
#include <limits.h>
#include <stdint.h>

void ueum_remove_last_char(char *str) {
    if (!str) {
        return;
    }

    str[strlen(str) - 1] = '\0';
}

bool ueum_last_char_is(const char *str, char c) {
    return (!str || str[strlen(str) - 1] != c) ? false : true;
}

char *ueum_strcat_variadic(const char *format, ...) {
    ueum_string_builder *s;
    va_list ap;
    size_t i;
    char c, *src, *concatenated;
    int d;
    double f;
    int64_t L;
    long int l;
    unsigned int u;

    ei_check_parameter_or_return(format);

    src = NULL;
    concatenated = NULL;

    for (i = 0; i < strlen(format); i++) {
        if (format[i] != 's' && format[i] != 'd' && format[i] != 'L' &&
            format[i] != 'l' && format[i] != 'f' && format[i] != 'c' &&
            format[i] != 'u') {
            ei_stacktrace_push_msg(
                "Specified format isn't valid. It must be contains only characters 's', 'd', 'L', 'l', 'f', 'c' and 'u'");
            return NULL;
        }
    }

    if ((s = ueum_string_builder_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create empty string builder");
        return NULL;
    }

    va_start(ap, format);
    while (*format) {
        switch (*format++) {
        case 's':
            src = va_arg(ap, char *);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                src = NULL;
                break;
            }
            src = NULL;
            break;

        case 'd':
            d = va_arg(ap, int);
            ueum_safe_alloc(src, char, 10);
            sprintf(src, "%d", d);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;

        case 'L':
            L = va_arg(ap, long long int);
            ueum_safe_alloc(src, char, 20);
#if defined(_WIN32) || defined(_WIN64)
#if defined(__GNUC__)
            _Pragma("GCC diagnostic push")
            _Pragma("GCC diagnostic ignored \"-Wformat\"")
#endif
                sprintf(src, "%I64d", L);
#if defined(__GNUC__)
            _Pragma("GCC diagnostic pop")
#endif
#else
            sprintf(src, "%lld", L);
#endif
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;

        case 'l':
            l = va_arg(ap, long int);
            ueum_safe_alloc(src, char, 20);
            sprintf(src, "%ld", l);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;

        case 'f':
            f = va_arg(ap, double);
            ueum_safe_alloc(src, char, 10);
            sprintf(src, "%f", f);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;

        case 'c':
            c = (char) va_arg(ap, int);
            ueum_safe_alloc(src, char, 2);
            sprintf(src, "%c", c);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;

        case 'u':
            u = va_arg(ap, unsigned int);
            ueum_safe_alloc(src, char, 10);
            sprintf(src, "%u", u);
            if (!ueum_string_builder_append(s, src, strlen(src))) {
                break;
            }
            ueum_safe_free(src);
            break;
        }
    }

    va_end(ap);

    if (s->data) {
        ueum_safe_alloc(concatenated, char, strlen(s->data) + 1);
        memcpy(concatenated, s->data, (strlen(s->data) + 1) * sizeof(char));
    }

    ueum_string_builder_destroy(s);

    return concatenated;
}

int ueum_find_str_in_data(char *data, const char *query) {
    size_t begin_pos, i, j, query_size;

    begin_pos = 0;
    query_size = strlen(query);

    for (i = 0, j = 0; i < strlen(data); i++) {
        if (j == 0) {
            begin_pos = i;
        }
        if (j == query_size) {
            return begin_pos;
        }
        if (data[i] == query[j]) {
            j++;
        } else {
            j = 0;
        }
    }

    return -1;
}

char *ueum_get_file_name_from_path(char *path) {
    char *file_name, *tmp_file_name;

    file_name = NULL;

    if (!strstr(path, "/")) {
        ueum_safe_alloc(file_name, char, strlen(path) + 1);
        strcpy(file_name, path);
        return file_name;
    }

    tmp_file_name = strrchr(path, '/');
    ueum_safe_alloc(file_name, char, strlen(tmp_file_name + 1) + 1);
    strcpy(file_name, tmp_file_name + 1);

    return file_name;
}

char *ueum_get_file_extension(char *path) {
    char *file_name, *tmp_file_name;

    file_name = NULL;

    if (!strstr(path, ".")) {
        ueum_safe_alloc(file_name, char, strlen(path) + 1);
        strcpy(file_name, path);
        return file_name;
    }

    tmp_file_name = strrchr(path, '.');
    ueum_safe_alloc(file_name, char, strlen(tmp_file_name + 1) + 1);
    strcpy(file_name, tmp_file_name + 1);

    return file_name;
}

char *ueum_string_create_from(const char *str) {
    char *new_str;

    new_str = NULL;

    ueum_safe_alloc(new_str, char, strlen(str) + 1);
    strcpy(new_str, str);

    return new_str;
}

char *ueum_string_create_from_bytes(unsigned char *bytes, size_t size) {
    char *string;

    string = NULL;

    ueum_safe_alloc(string, char, size + 1);
    memcpy(string, bytes, size * sizeof(char));

    return string;
}

char *ueum_append_dump_string(char *data, size_t max) {
    char *dump;

    if (max <= strlen(data)) {
        return ueum_string_create_from(data);
    }

    dump = NULL;

    ueum_safe_alloc(dump, char, max + 1);
    strcpy(dump, data);
    memset(dump + strlen(data), ' ', (max - strlen(data)) * sizeof(char));

    return dump;
}

bool ueum_starts_with(const char *pre, const char *str) {
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

int ueum_last_index_of(const char *string, char target) {
    int r;
    int current_index;

    r = -1;
    current_index = 0;

    while (string[current_index] != '\0') {
        if (string[current_index] == target) {
            r = current_index;
        }

        current_index++;
    }

    return r;
}

char *ueum_string_reverse(char *string) {
    char c;
    char *s0, *s1;

    s0 = string - 1;
    s1 = string;

    /* Find the end of the string */
    while (*s1) {
        ++s1;
    }

    /* Reverse it */
    while (s1-- > ++s0) {
        c = *s0;
        *s0 = *s1;
        *s1 = c;
    }

    return string;
}

bool ueum_int_to_string(int num, char *buffer, int radix) {
    int i, remainder;
    bool is_negative;

    i = 0;
    is_negative = false;

    /* Handle 0 explicitely, otherwise empty string is printed for 0 */
    if (num == 0) {
        buffer[i++] = '0';
        buffer[i] = '\0';
        return false;
    }

    /**
     * In standard itoa(), negative numbers are handled only with
     * radix 10. Otherwise numbers are considered unsigned.
     */
    if (num < 0 && radix == 10) {
        is_negative = true;
        num = -num;
    }

    /* Process individual digits */
    while (num != 0) {
        remainder = num % radix;
        buffer[i++] =
            (char)((remainder > 9) ? (remainder - 10) + 'a' : remainder + '0');
        num = num / radix;
    }

    /* If number is negative, append '-' */
    if (is_negative) {
        buffer[i++] = '-';
    }

    /* Append string terminator */
    buffer[i] = '\0';

    buffer = ueum_string_reverse(buffer);

    return true;
}

bool ueum_long_to_string(long num, char *buffer, int radix) {
    int i, remainder;
    bool is_negative;

    i = 0;
    is_negative = false;

    /* Handle 0 explicitely, otherwise empty string is printed for 0 */
    if (num == 0) {
        buffer[i++] = '0';
        buffer[i] = '\0';
        return false;
    }

    /**
     * In standard itoa(), negative numbers are handled only with
     * radix 10. Otherwise numbers are considered unsigned.
     */
    if (num < 0 && radix == 10) {
        is_negative = true;
        num = -num;
    }

    /* Process individual digits */
    while (num != 0) {
        remainder = num % radix;
        buffer[i++] =
            (char)((remainder > 9) ? (remainder - 10) + 'a' : remainder + '0');
        num = num / radix;
    }

    /* If number is negative, append '-' */
    if (is_negative) {
        buffer[i++] = '-';
    }

    /* Append string terminator */
    buffer[i] = '\0';

    buffer = ueum_string_reverse(buffer);

    return true;
}

bool ueum_string_to_int(char *string, int *out, int radix) {
    char *end;
    long l;    

    ei_check_parameter_or_return(string);

    if (string[0] == '\0' || isspace((unsigned char ) string[0])) {
        ei_stacktrace_push_msg("String is inconvertible");
        return false;
    }

    errno = 0;
    l = strtol(string, &end, radix);

    /* Both checks are needed because INT_MAX == LONG_MAX is possible. */
    if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX)) {
        ei_stacktrace_push_msg("String overflow");
        return false;
    }
    if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN)) {
        ei_stacktrace_push_msg("String underflow");
        return false;
    }
    if (*end != '\0') {
        ei_stacktrace_push_msg("String is inconvertible");
        return false;
    }

    *out = l;

    return true;
}

bool ueum_string_to_long(char *string, long *out, int radix) {
    char *end;
    long l;

    ei_check_parameter_or_return(string);

    if (string[0] == '\0' || isspace((unsigned char ) string[0])) {
        ei_stacktrace_push_msg("String is inconvertible");
        return false;
    }

    errno = 0;
    l = strtol(string, &end, radix);

    /* Both checks are needed because INT_MAX == LONG_MAX is possible. */
    if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX)) {
        ei_stacktrace_push_msg("String overflow");
        return false;
    }
    if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN)) {
        ei_stacktrace_push_msg("String underflow");
        return false;
    }
    if (*end != '\0') {
        ei_stacktrace_push_msg("String is inconvertible");
        return false;
    }

    *out = l;

    return true;
}

char *ueum_substring(char *string, size_t begin_index, size_t end_index) {
    size_t sub_length, length;
    char *new_string;

    length = strlen(string);
    new_string = NULL;

    if (end_index > length) {
        ei_stacktrace_push_msg("Index out of bounds");
        return NULL;
    }

    if (ueum__sub_sizet_overflow(end_index, begin_index, &sub_length)) {
        ei_stacktrace_push_msg("Buffer overflow detected when substracting end_index and begin_index");
        return NULL;
    }

    if (ueum__add_sizet_overflow(sub_length, 1, &sub_length)) {
        ei_stacktrace_push_msg("Buffer overflow detected when adding 1 to sub_length");
        return NULL;
    }

    if ((begin_index == 0) && (end_index == length)) {
        return ueum_string_create_from(string);
    }

    ueum_safe_alloc(new_string, char, length + 1);
    strncpy(new_string, string + begin_index, sub_length);
    return new_string;
}

char *ueum_get_until_symbol(char *str, int begin, char symbol, int *end) {
    char *line;
    int cr, line_size;
    size_t i, size;

    line = NULL;
    cr = -1;
    size = strlen(str);
    *end = -1;

    for (i = begin; i < size; i++) {
        if (str[i] == symbol) {
            cr = i;
            break;
        }
    }

    if (cr != -1) {
        line_size = cr - begin;
        ueum_safe_alloc(line, char, line_size + 1);
        memcpy(line, str + begin, line_size * sizeof(char));
    }

    *end = cr;

    return line;
}

char *ueum_trim_whitespace(char *str) {
    char *end;

    while (isspace((unsigned char )*str)) {
        str++;
    }

     /* All spaces? */
    if (*str == 0) {
        return str;
    }

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char )*end)) {
        end--;
    }

    /* Write new null terminator */
    *(end + 1) = 0;

    return str;
}

char *ueum_string_uppercase(const char *input) {
    char *output;
    size_t length, i;

    ei_check_parameter_or_return(input);

    output = NULL;
    length = strlen(input);

    ueum_safe_alloc(output, char, length+1);

    i = 0;
    for (i = 0; i < length; i++) {
        output[i] = (unsigned char)toupper((unsigned char)input[i]);
    }

    return output;
}
