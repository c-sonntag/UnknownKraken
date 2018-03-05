/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/init.h>
#include <unknownecho/defines.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/fileSystem/folder_utility.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/string/string_utility.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *resolve_out_folder_path() {
    char *working_dir_path, *working_dir_name, *out_folder_path;

    working_dir_path = NULL;
    working_dir_name = NULL;
    out_folder_path = NULL;

    working_dir_path = ue_get_current_dir();
    working_dir_name = ue_get_file_name_from_path(working_dir_path);
    if (strcmp(working_dir_name, UNKNOWNECHO_LIB_NAME) == 0) {
        out_folder_path = ue_string_create_from("out/");
    } else if(strcmp(working_dir_name, "bin") == 0) {
        out_folder_path = ue_string_create_from("../out/");
    }

    ue_safe_free(working_dir_path)
    ue_safe_free(working_dir_name)

    return out_folder_path;
}

static char *resolve_out_file_path(char *file_name) {
    char *out_folder_path, *out_file_path;

    if (!(out_folder_path = resolve_out_folder_path())) {
        fprintf(stderr, "[FATAL] Please run the program from project home or bin folder.\n");
        return NULL;
    }

    out_file_path = ue_strcat_variadic("ss", out_folder_path, file_name);

    ue_safe_free(out_folder_path)

    return out_file_path;
}

int main() {
    FILE *fp;
    char *out_file_path;

    ue_init();

    if (!(out_file_path = resolve_out_file_path("logger_example.log"))) {
        goto end;
    }

    fp = fopen(out_file_path, "w");
    ue_safe_free(out_file_path)

    ue_logger_trace("Loading library...");

    ue_logger_debug("Variable value is %d", 58);

    ue_logger_info("User %s is now connected", "username");

    ue_logger_warn("Loading time is consequently longer");

    ue_logger_error("Invalid password");

    ue_logger_fatal("Out of memory");

    fclose(fp);

end:
    ue_uninit();

    return 0;
}
