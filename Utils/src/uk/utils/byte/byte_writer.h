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

#ifndef UnknownKrakenUtils_BYTE_WRITER_H
#define UnknownKrakenUtils_BYTE_WRITER_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/byte/byte_stream_struct.h>

#include <stddef.h>

bool uk_utils_byte_writer_append_bytes(uk_utils_byte_stream *stream, unsigned char *bytes, size_t bytes_len);

bool uk_utils_byte_writer_append_string(uk_utils_byte_stream *stream, const char *string);

bool uk_utils_byte_writer_append_byte(uk_utils_byte_stream *stream, unsigned char byte);

bool uk_utils_byte_writer_append_int(uk_utils_byte_stream *stream, int n);

bool uk_utils_byte_writer_append_long(uk_utils_byte_stream *stream, long n);

bool uk_utils_byte_writer_append_stream(uk_utils_byte_stream *stream, uk_utils_byte_stream *to_copy);

#endif
