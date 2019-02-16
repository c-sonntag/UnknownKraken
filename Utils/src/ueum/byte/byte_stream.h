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

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_STREAM_H
#define UNKNOWNECHOUTILSMODULE_BYTE_STREAM_H

#include <ueum/byte/byte_stream_struct.h>
#include <ueum/compiler/bool.h>

#include <stddef.h>
#include <stdio.h>

ueum_byte_stream *ueum_byte_stream_create();

ueum_byte_stream *ueum_byte_stream_create_size(size_t limit);

void ueum_byte_stream_clean_up(ueum_byte_stream *stream);

void ueum_byte_stream_destroy(ueum_byte_stream *stream);

unsigned char *ueum_byte_stream_get_data(ueum_byte_stream *stream);

size_t ueum_byte_stream_get_position(ueum_byte_stream *stream);

bool ueum_byte_stream_set_position(ueum_byte_stream *stream, size_t position);

size_t ueum_byte_stream_get_size(ueum_byte_stream *stream);

bool ueum_byte_stream_is_empty(ueum_byte_stream *stream);

void ueum_byte_stream_print_hex(ueum_byte_stream *stream, FILE *fd);

void ueum_byte_stream_print_string(ueum_byte_stream *stream, FILE *fd);

ueum_byte_stream *ueum_byte_stream_copy(ueum_byte_stream *stream);

#endif
