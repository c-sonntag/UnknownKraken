/*******************************************************************************
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

#include <ms/ms.h>
#include <ms/utils/alloc.h>

#include <ei/ei.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define SLOT_ID 100
#define SLOT_NEW_CONTENT "new content !"
#define SLOT_NEW_SIZE 13

int main() {
    ms_slot *slot;

    ei_init();

    slot = NULL;

    ei_logger_info("Check if slot exist...");
    if (!ms_slot_exist_from_memory(SLOT_ID)) {
        if (ei_stacktrace_is_filled()) {
            ei_stacktrace_push_msg("Failed to check if slot exist");
            goto clean_up;
        }
        else {
            ei_logger_error("Specified slot doesn't exist");
            goto clean_up;
        }
    }
    ei_logger_info("Slot exist");

    ei_logger_info("Loading slot id %d...", SLOT_ID);
    if (!(slot = ms_slot_load_from_memory(SLOT_ID))) {
        ei_stacktrace_push_msg("Failed to load slot %d", SLOT_ID);
        goto clean_up;
    }
    ei_logger_info("Slot of size %ld loaded", slot->size);

    ms_slot_destroy(slot);
    slot = ms_slot_create_from_memory(SLOT_NEW_CONTENT, SLOT_NEW_SIZE);

    if (!ms_slot_save_to_memory(slot, SLOT_ID)) {
        ei_stacktrace_push_msg("Failed to save new slot content");
        goto clean_up;
    }

clean_up:
    ms_slot_destroy(slot);
    if (ei_stacktrace_is_filled()) {
        ei_logger_stacktrace("Stacktrace is filled with following error(s):");
    }
    ei_uninit();
    return 0;
}
