/******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                       *
 *                                                                            *
 * This file is part of LibMemoryPlugin.                                      *
 *                                                                            *
 *   LibMemoryPlugin is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by     *
 *   the Free Software Foundation, either version 3 of the License, or        *
 *   (at your option) any later version.                                      *
 *                                                                            *
 *   LibMemoryPlugin is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 *   GNU General Public License for more details.                             *
 *                                                                            *
 *   You should have received a copy of the GNU General Public License        *
 *   along with LibMemoryPlugin.  If not, see <http://www.gnu.org/licenses/>. *
 ******************************************************************************/

#include <mp/api/entry.h>

#include <ei/ei.h>

mp_entry *mp_entry_create() {
    mp_entry *entry;

    ueum_safe_alloc(entry, mp_entry, 1);
    entry->data = ueum_byte_stream_create();

    return entry;
}

void mp_entry_destroy(mp_entry *entry) {
    if (entry) {
        ueum_byte_stream_destroy(entry->data);
        ueum_safe_free(entry);
    }
}

bool mp_entry_add_stream(mp_entry *entry, ueum_byte_stream *data) {
    ei_check_parameter_or_return(entry);
    ei_check_parameter_or_return(entry->data);
    ei_check_parameter_or_return(data);

    if (!ueum_byte_writer_append_stream(entry->data, data)) {
        ei_stacktrace_push_msg("Failed to append new data to stream");
        return false;
    }

    return true;
}

bool mp_entry_add_bytes(mp_entry *entry, unsigned char *data, size_t data_size) {
    ei_check_parameter_or_return(entry);
    ei_check_parameter_or_return(entry->data);
    ei_check_parameter_or_return(data);
    ei_check_parameter_or_return(data_size > 0);

    if (!ueum_byte_writer_append_bytes(entry->data, data, data_size)) {
        ei_stacktrace_push_msg("Failed to append new data to stream");
        return false;
    }

    return true;
}

bool mp_entry_add_string(mp_entry *entry, const char *string) {
    ei_check_parameter_or_return(entry);
    ei_check_parameter_or_return(entry->data);
    ei_check_parameter_or_return(string);

    if (!ueum_byte_writer_append_string(entry->data, string)) {
        ei_stacktrace_push_msg("Failed to append new string to stream");
        return false;
    }

    return true;
}

bool mp_entry_add_file(mp_entry *entry, const char *file_name) {
    unsigned char *data;
    size_t size;

    ei_check_parameter_or_return(entry);
    ei_check_parameter_or_return(entry->data);
    ei_check_parameter_or_return(file_name);

    if (!ueum_is_file_exists(file_name)) {
        ei_stacktrace_push_msg("Cannot found specified file");
        return false;
    }

    if ((data = ueum_read_binary_file(file_name, &size)) == NULL) {
        ei_stacktrace_push_msg("Failed to read specified file as binary file");
        return false;
    }

    if (!ueum_byte_writer_append_bytes(entry->data, data, size)) {
        ei_stacktrace_push_msg("Failed to append file content to stream");
        ueum_safe_free(data);
        return false;
    }

    ueum_safe_free(data);

    return true;
}

ueum_byte_stream *mp_entry_get_data(mp_entry *entry) {
    ei_check_parameter_or_return(entry);
    ei_check_parameter_or_return(entry->data);

    return entry->data;
}
