/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#include <ueum/byte/hex_utility.h>
#include <ueum/safe/safe_alloc.h>

#include <string.h>

char *ueum_bytes_to_hex(unsigned char *bytes, size_t bytes_count) {
    char *hex;
    size_t i;

    ei_check_parameter_or_return(bytes);
    ei_check_parameter_or_return(bytes_count > 0);

    hex = NULL;

    ueum_safe_alloc(hex, char, bytes_count * 2 + 3);

    strcat(hex, "0x");
    for (i = 0; i < bytes_count; i++) {
        sprintf(hex + (i * 2) + 2, "%02x", bytes[i]);
    }

    return hex;
}

bool ueum_hex_print(unsigned char *bytes, size_t bytes_count, FILE *fd) {
    char *hex;

    ei_check_parameter_or_return(bytes);
    ei_check_parameter_or_return(bytes_count > 0);
    ei_check_parameter_or_return(fd);

    if ((hex = ueum_bytes_to_hex(bytes, bytes_count)) == NULL) {
        ei_stacktrace_push_msg("Failed to convert input bytes to hex string");
        return false;
    }

    fprintf(fd, "%s\n", hex);

    ueum_safe_free(hex);

    return true;
}
