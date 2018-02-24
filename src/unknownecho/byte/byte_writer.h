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
  *  @file      byte_writer.h
  *  @brief     Functions to append different data types into a byte stream.
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  *  @see       byte_stream_struct.h
  *  @see       byte_stream.h
  *  @see       byte_reader.h
  */

#ifndef UNKNOWNECHO_BYTE_WRITER_H
#define UNKNOWNECHO_BYTE_WRITER_H

#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream_struct.h>

#include <stddef.h>

bool ue_byte_writer_append_bytes(ue_byte_stream *stream, unsigned char *bytes, size_t bytes_len);

bool ue_byte_writer_append_string(ue_byte_stream *stream, char *string);

bool ue_byte_writer_append_byte(ue_byte_stream *stream, unsigned char byte);

bool ue_byte_writer_append_int(ue_byte_stream *stream, int n);

bool ue_byte_writer_append_long(ue_byte_stream *stream, long n);

bool ue_byte_writer_append_size_t(ue_byte_stream *stream, size_t n);

#endif
