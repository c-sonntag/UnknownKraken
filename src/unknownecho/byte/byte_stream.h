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

/**
 *  @file      byte_stream.h
 *  @brief     Byte stream base functions, to alloc/desalloc stream, and get/set fields.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       byte_stream_struct.h
 *  @see       byte_reader.h
 *  @see       byte_writer.h
 */

#ifndef UNKNOWNECHO_BYTE_STREAM_H
#define UNKNOWNECHO_BYTE_STREAM_H

#include <unknownecho/byte/byte_stream_struct.h>
#include <unknownecho/bool.h>

#include <stddef.h>
#include <stdio.h>

ue_byte_stream *ue_byte_stream_create();

ue_byte_stream *ue_byte_stream_create_size(size_t limit);

void ue_byte_stream_clean_up(ue_byte_stream *stream);

void ue_byte_stream_destroy(ue_byte_stream *stream);

unsigned char *ue_byte_stream_get_data(ue_byte_stream *stream);

size_t ue_byte_stream_get_position(ue_byte_stream *stream);

bool ue_byte_stream_set_position(ue_byte_stream *stream, size_t position);

size_t ue_byte_stream_get_size(ue_byte_stream *stream);

void ue_byte_stream_print_hex(ue_byte_stream *stream, FILE *fd);

void ue_byte_stream_print_string(ue_byte_stream *stream, FILE *fd);

#endif
