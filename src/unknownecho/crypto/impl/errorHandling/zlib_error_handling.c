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

#include <unknownecho/crypto/impl/errorHandling/zlib_error_handling.h>

#include <zlib.h>

void ue_zlib_error_handling_impl(int error_code) {
    switch (error_code) {
        case Z_ERRNO:
            if (ferror(stdin)) {
                ei_stacktrace_push_msg("Error reading stdin");
            } else if (ferror(stdout)) {
                ei_stacktrace_push_msg("Error reading stdout");
            }
        break;

        case Z_STREAM_ERROR:
            ei_stacktrace_push_msg("Invalid compression level");
        break;

        case Z_DATA_ERROR:
            ei_stacktrace_push_msg("Invalid or incomplete deflate data");
        break;

        case Z_MEM_ERROR:
            ei_stacktrace_push_msg("Out of memory");
        break;

        case Z_VERSION_ERROR:
            ei_stacktrace_push_msg("Zlib version mismatch");
        break;
    }
}
