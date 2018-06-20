/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoUtilsModule.										  *
 *																						  *
 *   LibUnknownEchoUtilsModule is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoUtilsModule is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoUtilsModule.  If not, see <http://www.gnu.org/licenses/>.   *
 ******************************************************************************************/

/**
 *  @file      byte_stream_struct.h
 *  @brief     Byte stream structure to quickly concatenate bytes and read different
 *			   types.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       byte_stream.h
 *  @see       ueum_byte_reader.h
 *  @see       ueum_byte_writer.h
 */

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_STREAM_STRUCT_H
#define UNKNOWNECHOUTILSMODULE_BYTE_STREAM_STRUCT_H

#include <stdint.h>

/**
 * @brief   stream of bytes
 *
 * The max size of the stream is position <= size <= limit.
 * The position is incremented when a data is read from the stream,
 * or wrote into.
 * The size is incremented and the field bytes in expand when the
 * the size isn't enough to write.
 * The is fixed at the creation of the stream, or 1024 by default.
 */
typedef struct {
	unsigned char *bytes; /** bytes of the stream */
    uint64_t limit; /** limit of the bytes field */
    uint64_t position; /** current position of the bytes field */
    uint64_t size; /** current max size of the stream */
} ueum_byte_stream;

#endif
