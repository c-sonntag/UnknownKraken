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

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_WRITER_H
#define UNKNOWNECHOUTILSMODULE_BYTE_WRITER_H

#include <ueum/compiler/bool.h>
#include <ueum/byte/byte_stream_struct.h>

#include <stddef.h>

bool ueum_byte_writer_append_bytes(ueum_byte_stream *stream, unsigned char *bytes, size_t bytes_len);

bool ueum_byte_writer_append_string(ueum_byte_stream *stream, const char *string);

bool ueum_byte_writer_append_byte(ueum_byte_stream *stream, unsigned char byte);

bool ueum_byte_writer_append_int(ueum_byte_stream *stream, int n);

bool ueum_byte_writer_append_long(ueum_byte_stream *stream, long n);

bool ueum_byte_writer_append_stream(ueum_byte_stream *stream, ueum_byte_stream *to_copy);

#endif
