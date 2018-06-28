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

#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/factory/hasher_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/api/hash/hasher.h>
#include <ei/ei.h>
#include <unknownecho/alloc.h>
#include <unknownecho/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>

ue_sym_key *ue_sym_key_create_random() {
	ue_sym_key *key;
	unsigned char *buf;
	size_t buf_size;

	key = NULL;
	buf_size = ue_sym_key_get_min_size();
	ue_safe_alloc(buf, unsigned char, buf_size);

	if (!ue_crypto_random_bytes(buf, buf_size)) {
		ei_stacktrace_push_msg("Failed to get crypto random bytes");
		ue_safe_free(buf);
		return NULL;
	}

	key = ue_sym_key_create(buf, buf_size);

	ue_safe_free(buf);

	return key;
}

ue_sym_key *ue_sym_key_create_from_file(char *file_path) {
	ei_stacktrace_push_msg("Not implemented");
	return NULL;
}

ue_sym_key *ue_sym_key_create_from_string(const char *string) {
    ue_sym_key *key;
    unsigned char *buf, *digest;
    ue_hasher *hasher;
    size_t digest_len;

    hasher = ue_hasher_default_create();

    buf = ue_bytes_create_from_string(string);

    digest = ue_hasher_digest(hasher, buf, strlen(string), &digest_len);

    key = ue_sym_key_create(digest, digest_len);

    ue_hasher_destroy(hasher);
    ue_safe_free(buf);
    ue_safe_free(digest);

    return key;
}
