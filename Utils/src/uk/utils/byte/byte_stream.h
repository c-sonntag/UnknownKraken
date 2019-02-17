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

#ifndef UnknownKrakenUtils_BYTE_STREAM_H
#define UnknownKrakenUtils_BYTE_STREAM_H

#include <uk/utils/byte/byte_stream_struct.h>
#include <uk/utils/compiler/bool.h>

#include <stddef.h>
#include <stdio.h>

uk_utils_byte_stream *uk_utils_byte_stream_create();

uk_utils_byte_stream *uk_utils_byte_stream_create_size(size_t limit);

void uk_utils_byte_stream_clean_up(uk_utils_byte_stream *stream);

void uk_utils_byte_stream_destroy(uk_utils_byte_stream *stream);

unsigned char *uk_utils_byte_stream_get_data(uk_utils_byte_stream *stream);

size_t uk_utils_byte_stream_get_position(uk_utils_byte_stream *stream);

bool uk_utils_byte_stream_set_position(uk_utils_byte_stream *stream, size_t position);

size_t uk_utils_byte_stream_get_size(uk_utils_byte_stream *stream);

bool uk_utils_byte_stream_is_empty(uk_utils_byte_stream *stream);

void uk_utils_byte_stream_print_hex(uk_utils_byte_stream *stream, FILE *fd);

void uk_utils_byte_stream_print_string(uk_utils_byte_stream *stream, FILE *fd);

uk_utils_byte_stream *uk_utils_byte_stream_copy(uk_utils_byte_stream *stream);

#endif
