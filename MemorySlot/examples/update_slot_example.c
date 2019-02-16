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

#include <ms/ms.h>
#include <ueum/ueum.h>

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
