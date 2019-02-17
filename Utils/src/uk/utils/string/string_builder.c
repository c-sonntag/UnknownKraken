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

#include <uk/utils/string/string_builder.h>
#include <uk/utils/safe/safe_alloc.h>
#include <uk/utils/ei.h>

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>

uk_utils_string_builder *uk_utils_string_builder_create() {
    return uk_utils_string_builder_create_size(1);
}

uk_utils_string_builder *uk_utils_string_builder_create_size(size_t max_size) {
    uk_utils_string_builder *builder;

    uk_utils_check_parameter_or_return(max_size > 0);

    builder = NULL;

    uk_utils_safe_alloc(builder, uk_utils_string_builder, 1);

    uk_utils_safe_alloc_or_goto(builder->data, char, max_size + 1, clean_up);

    memset(builder->data, 0, max_size);
    builder->max_size = max_size;
    builder->position = 0;

    return builder;

clean_up:
    uk_utils_string_builder_destroy(builder);
    return NULL;
}

bool uk_utils_string_builder_append(uk_utils_string_builder *s, char *data, size_t data_len) {
    uk_utils_check_parameter_or_return(s);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_len > 0 && data_len != 18446744073709551615UL);

    if ((data_len + s->position) > s->max_size) {
        uk_utils_safe_realloc(s->data, char, s->max_size, data_len + 1);
        s->max_size += data_len + 1;
    }

    memcpy(s->data + s->position, data, data_len);

    s->position += data_len;

    return true;
}

bool uk_utils_string_builder_append_variadic(uk_utils_string_builder *s, const char *format, ...) {
    bool result;
    va_list args;
    char *buffer;

    result = false;
    buffer = NULL;

    uk_utils_safe_alloc(buffer, char, 8192);

    va_start(args, format);
    vsnprintf(buffer, 8192, format, args);
    va_end(args);

    if ((result = uk_utils_string_builder_append(s, buffer, strlen(buffer))) == false) {
        uk_utils_stacktrace_push_msg("Failed to append concatenated args");
    }

    uk_utils_safe_free(buffer);

    return result;
}

void uk_utils_string_builder_clean_up(uk_utils_string_builder *s) {
    if (!s) {
        return;
    }

    if (!s->data) {
        return;
    }

    memset(s->data, 0, s->max_size);
    s->position = 0;
}

void uk_utils_string_builder_destroy(uk_utils_string_builder *s) {
    if (!s) {
        return;
    }

    uk_utils_safe_free(s->data);
    uk_utils_safe_free(s);
}

char *uk_utils_string_builder_get_data(uk_utils_string_builder *s) {
    if (!s || !s->data) {
        return NULL;
    }

    return s->data;
}

size_t uk_utils_string_builder_get_position(uk_utils_string_builder *s) {
    if (!s) {
        uk_utils_stacktrace_push_msg("Specified string builder ptr is null");
        return 0;
    }

    return s->position;
}
