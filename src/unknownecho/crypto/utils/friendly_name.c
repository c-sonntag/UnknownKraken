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

#include <unknownecho/crypto/utils/friendly_name.h>
#include <ei/ei.h>
#include <unknownecho/alloc.h>

#include <string.h>

unsigned char *ue_friendly_name_build(unsigned char *nickname, size_t nickname_size, const char *keystore_type, size_t *friendly_name_size) {
	unsigned char *friendly_name;

	ei_check_parameter_or_return(nickname);
	ei_check_parameter_or_return(nickname_size > 0);
	ei_check_parameter_or_return(keystore_type);

	*friendly_name_size = nickname_size + 1 + strlen(keystore_type);
	ue_safe_alloc(friendly_name, unsigned char, *friendly_name_size);
	memcpy(friendly_name, nickname, nickname_size * sizeof(unsigned char));
	memcpy(friendly_name + nickname_size, "_", sizeof(unsigned char));
	memcpy(friendly_name + nickname_size + 1, keystore_type, strlen(keystore_type) * sizeof(unsigned char));

	return friendly_name;
}
