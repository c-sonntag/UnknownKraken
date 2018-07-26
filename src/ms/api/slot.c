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

#include <ms/api/slot.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <ms/impl/win/resource.h>
#endif

#include <ei/ei.h>

#include <string.h>

ms_slot *ms_slot_create_from_file(const char *file_name) {
    ms_slot *slot;

    ei_check_parameter_or_return(file_name);

    if (!ueum_is_file_exists(file_name)) {
        ei_stacktrace_push_msg("Specified file doesn't exist");
        return NULL;
    }

    slot = NULL;

    ueum_safe_alloc(slot, ms_slot, 1);
    
    if (!(slot->data = ueum_read_binary_file(file_name, &slot->size))) {
        ei_stacktrace_push_msg("Failed to read specified file '%s'", file_name);
        ueum_safe_free(slot);
        return NULL;
    }

    slot->id = -1;
    slot->state = MS_SLOT_AVAILABLE;

    return slot;
}

ms_slot *ms_slot_create_from_memory(unsigned char *buffer, size_t size) {
    ms_slot *slot;

    ei_check_parameter_or_return(buffer);
    ei_check_parameter_or_return(size > 0);

    slot = NULL;

    ueum_safe_alloc(slot, ms_slot, 1);
    ueum_safe_alloc(slot->data, unsigned char, size);
    memcpy(slot->data, buffer, size * sizeof(unsigned char));
    slot->size = size;
    slot->id = -1;
    slot->state = MS_SLOT_AVAILABLE;

    return slot;
}

void ms_slot_destroy(ms_slot *slot) {
    if (slot) {
        ueum_safe_free(slot->data);
        ueum_safe_free(slot);
    }
}

int ms_slot_get_id(ms_slot *slot) {
    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return slot->id;
}

ms_slot_state ms_slot_get_state(ms_slot *slot) {
    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return MS_SLOT_UNKNOWN;
    }

    return slot->state;
}

unsigned char *ms_slot_get_data(ms_slot *slot) {
    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return NULL;
    }

    return slot->data;
}

size_t ms_slot_get_size(ms_slot *slot) {
    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return 0;
    }

    return slot->size;
}

bool ms_slot_save_to_file(ms_slot *slot, int id, const char *file_name) {
    ei_check_parameter_or_return(slot);
    ei_check_parameter_or_return(slot->data);
    ei_check_parameter_or_return(slot->size);
    ei_check_parameter_or_return(id > 0);
    ei_check_parameter_or_return(file_name);

    if (slot->state == MS_SLOT_UNKNOWN) {
        ei_logger_warn("The state of the slot is unknown");
    }
    else if (slot->state != MS_SLOT_AVAILABLE) {
        ei_stacktrace_push_msg("The specified slot is unavailable");
        return false;
    }

    if (!ms_resource_save(file_name, slot->data, slot->size, id)) {
        ei_stacktrace_push_msg("Failed to save slot as resource");
        slot->state = MS_SLOT_CORRUPTED;
        return false;
    }

    slot->state = MS_SLOT_USED;

    return true;
}

bool ms_slot_save_to_memory(ms_slot *slot, int id) {
    char *our_process_name;

    ei_check_parameter_or_return(slot);
    ei_check_parameter_or_return(slot->data);
    ei_check_parameter_or_return(slot->size);
    ei_check_parameter_or_return(id > 0);

    if (slot->state == MS_SLOT_UNKNOWN) {
        ei_logger_warn("The state of the slot is unknown");
    }
    else if (slot->state != MS_SLOT_AVAILABLE) {
        ei_stacktrace_push_msg("The specified slot is unavailable");
        return false;
    }

    if (!(our_process_name = ueum_get_current_process_name())) {
        ei_stacktrace_push_msg("Failed to get current process name");
        return false;
    }

    if (!ms_resource_save(our_process_name, slot->data, slot->size, id)) {
        ei_stacktrace_push_msg("Failed to save slot as resource");
        slot->state = MS_SLOT_CORRUPTED;
        ueum_safe_free(our_process_name);
        return false;
    }

    slot->state = MS_SLOT_USED;
    ueum_safe_free(our_process_name);

    return true;
}

ms_slot *ms_slot_load_from_memory(int id) {
    ms_slot *slot;

    slot = NULL;

    ei_check_parameter_or_return(id > 0);

    ueum_safe_alloc(slot, ms_slot, 1);
    
    if (!(slot->data = ms_resource_load_from_memory(id, &slot->size))) {
        ueum_safe_free(slot);
        ei_stacktrace_push_msg("Failed to resource from id %d", id);
        return NULL;
    }

    slot->id = id;
    slot->state = MS_SLOT_USED;

    return slot;
}

bool ms_slot_exist_from_file(int id, const char *file_name) {
    if (!ms_resource_exist(file_name, id)) {
        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to check if the resource exist");
        }

        return false;
    }

    return true;
}

bool ms_slot_exist_from_memory(int id) {
    char *our_process_name;

    if (!(our_process_name = ueum_get_current_process_name())) {
        ei_stacktrace_push_msg("Failed to get current process name");
        return false;
    }

    if (!ms_resource_exist(our_process_name, id)) {
        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to check if the resource exist");
        }

        return false;
    }

    return true;
}

int ms_slot_find_id_from_path(const char *file_name, ms_slot *slot) {
    if (!file_name) {
        ei_stacktrace_push_msg("Specified file_name ptr is null");
        return -1;
    }

    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return ms_resource_find_id_from_path(file_name, slot->data, slot->size);
}

int ms_slot_find_id_from_memory(ms_slot *slot) {
    if (!slot) {
        ei_stacktrace_push_msg("Specified slot ptr is null");
        return -1;
    }

    return ms_resource_find_id_from_memory(slot->data, slot->size);
}

int *ms_slot_find_ids_from_file(const char *file_name, int *number) {
    int *ids, temp_number;

    temp_number = 0;

    if (!(ids = ms_resource_find_ids_from_path(file_name, &temp_number))) {
        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to list all ids of specified file");
        }
        return NULL;
    }

    *number = temp_number;

    return ids;
}

int *ms_slot_find_ids_from_memory(int *number) {
    int *ids, temp_number;

    temp_number = 0;

    if (!(ids = ms_resource_find_ids_from_memory(&temp_number))) {
        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to list all ids of current object");
        }
        return NULL;
    }

    *number = temp_number;

    return ids;
}
