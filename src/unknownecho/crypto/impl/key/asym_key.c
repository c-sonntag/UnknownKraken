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

#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

ue_asym_key *ue_asym_key_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_key *akey;

	ue_safe_alloc(akey, ue_asym_key, 1)
	akey->pk = pk;
	akey->sk = sk;

	return akey;
}

void ue_asym_key_destroy(ue_asym_key *akey){
	ue_safe_free(akey);
}


void ue_asym_key_destroy_all(ue_asym_key *akey){
	if (akey) {
		ue_public_key_destroy(akey->pk);
		ue_private_key_destroy(akey->sk);
		ue_safe_free(akey);
	}
}

bool ue_asym_key_is_valid(ue_asym_key *akey){
	return akey && akey->pk && akey->sk &&
		ue_public_key_is_valid(akey->pk) &&
		ue_private_key_is_valid(akey->sk);
}

bool ue_asym_key_print(ue_asym_key *akey, FILE *out_fd, unsigned char *passphrase, size_t passphrase_size) {
	if (!akey || !akey->pk || !akey->sk) {
		return false;
	}

	ue_public_key_print(akey->pk, out_fd);
    ue_private_key_print(akey->sk, out_fd, passphrase, passphrase_size);

	return true;
}
