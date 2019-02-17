/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibMemoryPlugin.                                       *
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

#include <uk/mp/api/entry.h>

#include <uk/utils/ei.h>

uk_mp_entry *uk_mp_entry_create() {
    uk_mp_entry *entry;

    uk_utils_safe_alloc(entry, uk_mp_entry, 1);
    entry->data = uk_utils_byte_stream_create();

    return entry;
}

void uk_mp_entry_destroy(uk_mp_entry *entry) {
    if (entry) {
        uk_utils_byte_stream_destroy(entry->data);
        uk_utils_safe_free(entry);
    }
}

bool uk_mp_entry_add_stream(uk_mp_entry *entry, uk_utils_byte_stream *data) {
    uk_utils_check_parameter_or_return(entry);
    uk_utils_check_parameter_or_return(entry->data);
    uk_utils_check_parameter_or_return(data);

    if (!uk_utils_byte_writer_append_stream(entry->data, data)) {
        uk_utils_stacktrace_push_msg("Failed to append new data to stream");
        return false;
    }

    return true;
}

bool uk_mp_entry_add_bytes(uk_mp_entry *entry, unsigned char *data, size_t data_size) {
    uk_utils_check_parameter_or_return(entry);
    uk_utils_check_parameter_or_return(entry->data);
    uk_utils_check_parameter_or_return(data);
    uk_utils_check_parameter_or_return(data_size > 0);

    if (!uk_utils_byte_writer_append_bytes(entry->data, data, data_size)) {
        uk_utils_stacktrace_push_msg("Failed to append new data to stream");
        return false;
    }

    return true;
}

bool uk_mp_entry_add_string(uk_mp_entry *entry, const char *string) {
    uk_utils_check_parameter_or_return(entry);
    uk_utils_check_parameter_or_return(entry->data);
    uk_utils_check_parameter_or_return(string);

    if (!uk_utils_byte_writer_append_string(entry->data, string)) {
        uk_utils_stacktrace_push_msg("Failed to append new string to stream");
        return false;
    }

    return true;
}

bool uk_mp_entry_add_file(uk_mp_entry *entry, const char *file_name) {
    unsigned char *data;
    size_t size;

    uk_utils_check_parameter_or_return(entry);
    uk_utils_check_parameter_or_return(entry->data);
    uk_utils_check_parameter_or_return(file_name);

    if (!uk_utils_is_file_exists(file_name)) {
        uk_utils_stacktrace_push_msg("Cannot found specified file");
        return false;
    }

    if ((data = uk_utils_read_binary_file(file_name, &size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to read specified file as binary file");
        return false;
    }

    if (!uk_utils_byte_writer_append_bytes(entry->data, data, size)) {
        uk_utils_stacktrace_push_msg("Failed to append file content to stream");
        uk_utils_safe_free(data);
        return false;
    }

    uk_utils_safe_free(data);

    return true;
}

uk_utils_byte_stream *uk_mp_entry_get_data(uk_mp_entry *entry) {
    uk_utils_check_parameter_or_return(entry);
    uk_utils_check_parameter_or_return(entry->data);

    return entry->data;
}
