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
#include <ueum/ueum.h>

#include <ei/ei.h>

#include <string.h>

#define SOURCE_FILE "data.txt"
#define CONTENT_FILE "Hello world !"
#define DESTINATION_FILE "load_slot_example.exe"
#define SLOT_ID 100

int main(int argc, char **argv) {
    ms_slot *slot;
    FILE *fd;

    ei_init();

    slot = NULL;
    fd = NULL;

    if (!ueum_is_file_exists(SOURCE_FILE)) {
        ei_logger_info("File %s doesn't exist. Creating it...", SOURCE_FILE);

        if (!(fd = fopen(SOURCE_FILE, "w"))) {
            ei_stacktrace_push_errno();
            goto clean_up;
        }

        if (fwrite(CONTENT_FILE, strlen(CONTENT_FILE), 1, fd) != 1) {
            ei_stacktrace_push_errno();
            fclose(fd);
            goto clean_up;
        }

        fclose(fd);
    }

    ei_logger_info("Loading slot from file '%s'...", SOURCE_FILE);
    if (!(slot = ms_slot_create_from_file(SOURCE_FILE))) {
        ei_stacktrace_push_msg("Failed to create slot from file '%s'", SOURCE_FILE);
        goto clean_up;
    }
    ei_logger_info("Slot loaded.");

    ei_logger_info("Saving slot...");
    if (!ms_slot_save_to_file(slot, SLOT_ID, argv[1])) {
        ei_stacktrace_push_msg("Failed to save slot to file '%s'", argv[1]);
        goto clean_up;
    }
    ei_logger_info("Slot saved to file '%s'.", argv[1]);
    
clean_up:
    ms_slot_destroy(slot);
    if (ei_stacktrace_is_filled()) {
        ei_logger_stacktrace("Stacktrace is filled with following error(s):");
    }
    ei_uninit();
    return 0;
}
