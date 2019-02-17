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

#include <string.h>

#define SOURCE_FILE "data.txt"
#define CONTENT_FILE "Hello world !"
#define DESTINATION_FILE "load_slot_example.exe"
#define SLOT_ID 100

int main(int argc, char **argv) {
    uk_ms_slot *slot;
    FILE *fd;

    uk_utils_init();

    slot = NULL;
    fd = NULL;

    if (!uk_utils_is_file_exists(SOURCE_FILE)) {
        uk_utils_logger_info("File %s doesn't exist. Creating it...", SOURCE_FILE);

        if (!(fd = fopen(SOURCE_FILE, "w"))) {
            uk_utils_stacktrace_push_errno();
            goto clean_up;
        }

        if (fwrite(CONTENT_FILE, strlen(CONTENT_FILE), 1, fd) != 1) {
            uk_utils_stacktrace_push_errno();
            fclose(fd);
            goto clean_up;
        }

        fclose(fd);
    }

    uk_utils_logger_info("Loading slot from file '%s'...", SOURCE_FILE);
    if (!(slot = uk_ms_slot_create_from_file(SOURCE_FILE))) {
        uk_utils_stacktrace_push_msg("Failed to create slot from file '%s'", SOURCE_FILE);
        goto clean_up;
    }
    uk_utils_logger_info("Slot loaded.");

    uk_utils_logger_info("Saving slot...");
    if (!uk_ms_slot_save_to_file(slot, SLOT_ID, argv[1])) {
        uk_utils_stacktrace_push_msg("Failed to save slot to file '%s'", argv[1]);
        goto clean_up;
    }
    uk_utils_logger_info("Slot saved to file '%s'.", argv[1]);
    
clean_up:
    uk_ms_slot_destroy(slot);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_stacktrace("Stacktrace is filled with following error(s):");
    }
    uk_utils_uninit();
    return 0;
}
