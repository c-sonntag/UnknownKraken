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
 *  @file      byte_utility.h
 *  @brief     Byte manipulation utility functions, to convert from/to bytes in another type.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOUTILSMODULE_BYTE_UTILITY_H
#define UNKNOWNECHOUTILSMODULE_BYTE_UTILITY_H

#include <ueum/bool.h>

#include <stddef.h>

unsigned char *ueum_bytes_create_from_string(const char *str);

unsigned char *ueum_bytes_create_from_bytes(unsigned char *bytes, size_t size);

void ueum_int_to_bytes(int n, unsigned char *bytes);

int ueum_bytes_to_int(unsigned char *bytes);

bool ueum_bytes_starts_with(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size);

bool ueum_bytes_contains(unsigned char *data, size_t data_size, unsigned char *target, size_t target_size);

#endif
