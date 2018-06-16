/******************************************************************************
* Copyright (C) 2018 by Charly Lamothe                                        *
*                                                                             *
* This file is part of LibMemorySlot.                                         *
*                                                                             *
*   LibMemorySlot is free software: you can redistribute it and/or modify     *
*   it under the terms of the GNU General Public License as published by      *
*   the Free Software Foundation, either version 3 of the License, or         *
*   (at your option) any later version.                                       *
*                                                                             *
*   LibMemorySlot is distributed in the hope that it will be useful,          *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
*   GNU General Public License for more details.                              *
*                                                                             *
*   You should have received a copy of the GNU General Public License         *
*   along with LibMemorySlot.  If not, see <http://www.gnu.org/licenses/>.    *
*******************************************************************************/

#include <ms/api/slot.h>
#include <ms/utils/alloc.h>
#include <ms/utils/file_utils.h>
#include <ms/utils/process_utils.h>

#if defined(_WIN32) || defined(_WIN64)
	#include <ms/impl/win/resource.h>
#endif

#include <ei/ei.h>

#include <string.h>

ms_slot *ms_slot_create_from_file(const char *file_name) {
	ms_slot *slot;

	ei_check_parameter_or_return(file_name);

	if (!ms_is_file_exists(file_name)) {
		ei_stacktrace_push_msg("Specified file doesn't exist");
		return NULL;
	}

	ms_safe_alloc(slot, ms_slot, 1);
	
	if (!(slot->data = ms_read_binary_file(file_name, &slot->size))) {
		ei_stacktrace_push_msg("Failed to read specified file '%s'", file_name);
		ms_safe_free(slot);
		return NULL;
	}

	slot->id = -1;
	slot->state = MS_SLOT_AVAILABLE;

	return slot;
}

ms_slot *ms_slot_create_from_memory(unsigned char **buffer, size_t size) {
	ms_slot *slot;

	ei_check_parameter_or_return(buffer);
	ei_check_parameter_or_return(size > 0);

	ms_safe_alloc(slot, ms_slot, 1);
	ms_safe_alloc(slot->data, unsigned char, size);
	memcpy(slot->data, buffer, size * sizeof(unsigned char));
	slot->size = size;
	slot->id = -1;
	slot->state = MS_SLOT_AVAILABLE;

	return slot;
}

void ms_slot_destroy(ms_slot *slot) {
	if (slot) {
		ms_safe_free(slot->data);
		ms_safe_free(slot);
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

	if (!(our_process_name = ms_get_current_process_name())) {
		ei_stacktrace_push_msg("Failed to get current process name");
		return false;
	}

	if (!ms_resource_save(our_process_name, slot->data, slot->size, id)) {
		ei_stacktrace_push_msg("Failed to save slot as resource");
		slot->state = MS_SLOT_CORRUPTED;
		ms_safe_free(our_process_name);
		return false;
	}

	slot->state = MS_SLOT_USED;
	ms_safe_free(our_process_name);

	return true;
}

ms_slot *ms_slot_load_from_memory(int id) {
	ms_slot *slot;

	ei_check_parameter_or_return(id > 0);

	ms_safe_alloc(slot, ms_slot, 1);
	
	if (!(slot->data = ms_resource_load_from_memory(id, &slot->size))) {
		ms_safe_free(slot);
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

	if (!(our_process_name = ms_get_current_process_name())) {
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
