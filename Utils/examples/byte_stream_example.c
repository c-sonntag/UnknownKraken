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

#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

int main() {
    uk_utils_byte_stream *x, *y, *z;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    /* Allocate streams */
    uk_utils_logger_info("Creating x, y and z byte streams");
    x = uk_utils_byte_stream_create();
    y = uk_utils_byte_stream_create();
    z = uk_utils_byte_stream_create();

    /* Create stream x with Hello world content */
    uk_utils_logger_info("Adding Hello world string to the stream x");
    uk_utils_byte_writer_append_string(x, "Hello world !");

    /* Copy x stream to y */
    uk_utils_logger_info("Write x stream to y stream");
    uk_utils_byte_writer_append_stream(y, x);

    /* Set the virtual cursor of y to the begining */
    uk_utils_byte_stream_set_position(y, 0);

    /* Read next datas as a stream and copy it to z */
    uk_utils_logger_info("Read y stream and copy it to z stream");
    uk_utils_byte_read_next_stream(y, z);

    /**
     * Print all streams in hexadecimals format.
     * It's excepted that x is equal to z. y is a little bigger
     * because it contains the size of x.
     */
    uk_utils_logger_info("Print the content of the streams in hex format. y is a little bigger that x and z because it contains the size of x.");
    uk_utils_byte_stream_print_hex(x, stdout);
    uk_utils_byte_stream_print_hex(y, stdout);
    uk_utils_byte_stream_print_hex(z, stdout);

    /* Clean-up streams */
    uk_utils_byte_stream_destroy(x);
    uk_utils_byte_stream_destroy(y);
    uk_utils_byte_stream_destroy(z);

    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }

    uk_utils_uninit();

    return 0;
}
