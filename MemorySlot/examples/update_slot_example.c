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

#include <uk/ms/ms.h>
#include <uk/utils/ueum.h>

#include <uk/utils/ei.h>

#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define SLOT_ID 100
#define SLOT_NEW_CONTENT "new content !"
#define SLOT_NEW_SIZE 13

int main() {
    uk_ms_slot *slot;

    uk_utils_init();

    slot = NULL;

    uk_utils_logger_info("Check if slot exist...");
    if (!uk_ms_slot_exist_from_memory(SLOT_ID)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_stacktrace_push_msg("Failed to check if slot exist");
            goto clean_up;
        }
        else {
            uk_utils_logger_error("Specified slot doesn't exist");
            goto clean_up;
        }
    }
    uk_utils_logger_info("Slot exist");

    uk_utils_logger_info("Loading slot id %d...", SLOT_ID);
    if (!(slot = uk_ms_slot_load_from_memory(SLOT_ID))) {
        uk_utils_stacktrace_push_msg("Failed to load slot %d", SLOT_ID);
        goto clean_up;
    }
    uk_utils_logger_info("Slot of size %ld loaded", slot->size);

    uk_ms_slot_destroy(slot);
    slot = uk_ms_slot_create_from_memory(SLOT_NEW_CONTENT, SLOT_NEW_SIZE);

    if (!uk_ms_slot_save_to_memory(slot, SLOT_ID)) {
        uk_utils_stacktrace_push_msg("Failed to save new slot content");
        goto clean_up;
    }

clean_up:
    uk_ms_slot_destroy(slot);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_stacktrace("Stacktrace is filled with following error(s):");
    }
    uk_utils_uninit();
    return 0;
}
