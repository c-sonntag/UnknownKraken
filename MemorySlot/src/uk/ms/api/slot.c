/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibMemorySlot.                                         *
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

#include <uk/ms/api/slot.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <uk/ms/impl/win/resource.h>
#endif

#include <uk/utils/ei.h>

#include <string.h>

uk_ms_slot *uk_ms_slot_create_from_file(const char *file_name) {
    uk_ms_slot *slot;

    uk_utils_check_parameter_or_return(file_name);

    if (!uk_utils_is_file_exists(file_name)) {
        uk_utils_stacktrace_push_msg("Specified file doesn't exist");
        return NULL;
    }

    slot = NULL;

    uk_utils_safe_alloc(slot, uk_ms_slot, 1);
    
    if (!(slot->data = uk_utils_read_binary_file(file_name, &slot->size))) {
        uk_utils_stacktrace_push_msg("Failed to read specified file '%s'", file_name);
        uk_utils_safe_free(slot);
        return NULL;
    }

    slot->id = -1;
    slot->state = MS_SLOT_AVAILABLE;

    return slot;
}

uk_ms_slot *uk_ms_slot_create_from_memory(unsigned char *buffer, size_t size) {
    uk_ms_slot *slot;

    uk_utils_check_parameter_or_return(buffer);
    uk_utils_check_parameter_or_return(size > 0);

    slot = NULL;

    uk_utils_safe_alloc(slot, uk_ms_slot, 1);
    uk_utils_safe_alloc(slot->data, unsigned char, size);
    memcpy(slot->data, buffer, size * sizeof(unsigned char));
    slot->size = size;
    slot->id = -1;
    slot->state = MS_SLOT_AVAILABLE;

    return slot;
}

void uk_ms_slot_destroy(uk_ms_slot *slot) {
    if (slot) {
        uk_utils_safe_free(slot->data);
        uk_utils_safe_free(slot);
    }
}

int uk_ms_slot_get_id(uk_ms_slot *slot) {
    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return slot->id;
}

uk_ms_slot_state uk_ms_slot_get_state(uk_ms_slot *slot) {
    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return MS_SLOT_UNKNOWN;
    }

    return slot->state;
}

unsigned char *uk_ms_slot_get_data(uk_ms_slot *slot) {
    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return NULL;
    }

    return slot->data;
}

size_t uk_ms_slot_get_size(uk_ms_slot *slot) {
    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return 0;
    }

    return slot->size;
}

bool uk_ms_slot_save_to_file(uk_ms_slot *slot, int id, const char *file_name) {
    uk_utils_check_parameter_or_return(slot);
    uk_utils_check_parameter_or_return(slot->data);
    uk_utils_check_parameter_or_return(slot->size);
    uk_utils_check_parameter_or_return(id > 0);
    uk_utils_check_parameter_or_return(file_name);

    if (slot->state == MS_SLOT_UNKNOWN) {
        uk_utils_logger_warn("The state of the slot is unknown");
    }
    else if (slot->state != MS_SLOT_AVAILABLE) {
        uk_utils_stacktrace_push_msg("The specified slot is unavailable");
        return false;
    }

    if (!uk_ms_resource_save(file_name, slot->data, slot->size, id)) {
        uk_utils_stacktrace_push_msg("Failed to save slot as resource");
        slot->state = MS_SLOT_CORRUPTED;
        return false;
    }

    slot->state = MS_SLOT_USED;

    return true;
}

bool uk_ms_slot_save_to_memory(uk_ms_slot *slot, int id) {
    char *our_process_name;

    uk_utils_check_parameter_or_return(slot);
    uk_utils_check_parameter_or_return(slot->data);
    uk_utils_check_parameter_or_return(slot->size);
    uk_utils_check_parameter_or_return(id > 0);

    if (slot->state == MS_SLOT_UNKNOWN) {
        uk_utils_logger_warn("The state of the slot is unknown");
    }
    else if (slot->state != MS_SLOT_AVAILABLE) {
        uk_utils_stacktrace_push_msg("The specified slot is unavailable");
        return false;
    }

    if (!(our_process_name = uk_utils_get_current_process_name())) {
        uk_utils_stacktrace_push_msg("Failed to get current process name");
        return false;
    }

    if (!uk_ms_resource_save(our_process_name, slot->data, slot->size, id)) {
        uk_utils_stacktrace_push_msg("Failed to save slot as resource");
        slot->state = MS_SLOT_CORRUPTED;
        uk_utils_safe_free(our_process_name);
        return false;
    }

    slot->state = MS_SLOT_USED;
    uk_utils_safe_free(our_process_name);

    return true;
}

uk_ms_slot *uk_ms_slot_load_from_memory(int id) {
    uk_ms_slot *slot;

    slot = NULL;

    uk_utils_check_parameter_or_return(id > 0);

    uk_utils_safe_alloc(slot, uk_ms_slot, 1);
    
    if (!(slot->data = uk_ms_resource_load_from_memory(id, &slot->size))) {
        uk_utils_safe_free(slot);
        uk_utils_stacktrace_push_msg("Failed to resource from id %d", id);
        return NULL;
    }

    slot->id = id;
    slot->state = MS_SLOT_USED;

    return slot;
}

bool uk_ms_slot_exist_from_file(int id, const char *file_name) {
    if (!uk_ms_resource_exist(file_name, id)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_stacktrace_push_msg("Failed to check if the resource exist");
        }

        return false;
    }

    return true;
}

bool uk_ms_slot_exist_from_memory(int id) {
    char *our_process_name;

    if (!(our_process_name = uk_utils_get_current_process_name())) {
        uk_utils_stacktrace_push_msg("Failed to get current process name");
        return false;
    }

    if (!uk_ms_resource_exist(our_process_name, id)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_stacktrace_push_msg("Failed to check if the resource exist");
        }

        return false;
    }

    return true;
}

int uk_ms_slot_find_id_from_path(const char *file_name, uk_ms_slot *slot) {
    if (!file_name) {
        uk_utils_stacktrace_push_msg("Specified file_name ptr is null");
        return -1;
    }

    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return uk_ms_resource_find_id_from_path(file_name, slot->data, slot->size);
}

int uk_ms_slot_find_id_from_memory(uk_ms_slot *slot) {
    if (!slot) {
        uk_utils_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return uk_ms_resource_find_id_from_memory(slot->data, slot->size);
}

int *uk_ms_slot_find_ids_from_file(const char *file_name, int *number) {
    int *ids, teuk_mp_number;

    teuk_mp_number = 0;

    if (!(ids = uk_ms_resource_find_ids_from_path(file_name, &teuk_mp_number))) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_stacktrace_push_msg("Failed to list all ids of specified file");
        }
        return NULL;
    }

    *number = teuk_mp_number;

    return ids;
}

int *uk_ms_slot_find_ids_from_memory(int *number) {
    int *ids, teuk_mp_number;

    teuk_mp_number = 0;

    if (!(ids = uk_ms_resource_find_ids_from_memory(&teuk_mp_number))) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_stacktrace_push_msg("Failed to list all ids of current object");
        }
        return NULL;
    }

    *number = teuk_mp_number;

    return ids;
}
