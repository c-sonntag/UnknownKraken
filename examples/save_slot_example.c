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
*   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
*******************************************************************************/

#include <ms/ms.h>

#include <ei/ei.h>

#define SOURCE_FILE "data.txt"
#define DESTINATION_FILE "load_slot_example.exe"
#define SLOT_ID 100

int main() {
	ms_slot *slot;

	ei_init();

	slot = NULL;

	ei_logger_info("Loading slot from file '%s'...", SOURCE_FILE);
	if (!(slot = ms_slot_create_from_file(SOURCE_FILE))) {
		ei_stacktrace_push_msg("Failed to create slot from file '%s'", SOURCE_FILE);
		goto clean_up;
	}
	ei_logger_info("Slot loaded.");

	ei_logger_info("Saving slot...");
	if (!ms_slot_save_to_file(slot, SLOT_ID, DESTINATION_FILE)) {
		ei_stacktrace_push_msg("Failed to save slot to file '%s'", DESTINATION_FILE);
		goto clean_up;
	}
	ei_logger_info("Slot saved to file '%s'.", DESTINATION_FILE);
	
clean_up:
	ms_slot_destroy(slot);
	if (ei_stacktrace_is_filled()) {
		ei_logger_stacktrace("Stacktrace is filled with following error(s):");
		ei_uninit();
	}
	return 0;
}