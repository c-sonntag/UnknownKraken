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

#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>

ue_sym_encrypter *ue_sym_encrypter_aes_create(ue_sym_key *key) {
	ue_sym_encrypter *encrypter;

	if (!ue_sym_key_is_valid(key)) {
		ue_stacktrace_push_msg("Specified key is invalid");
		return NULL;
	}

	if (key->size < ue_sym_key_get_min_size()) {
		ue_stacktrace_push_msg("Specified key size is invalid. %d bytes is required.", ue_sym_key_get_min_size());
		return NULL;
	}

	encrypter = ue_sym_encrypter_create();
	encrypter->type = AES;
	encrypter->mode = AES_CBC;
	encrypter->key_size = 32;
	encrypter->iv_size = 16;
	encrypter->key = key;

	return encrypter;
}

ue_sym_encrypter *ue_sym_encrypter_default_create(ue_sym_key *key) {
	return ue_sym_encrypter_aes_create(key);
}
