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

#include <unknownecho/crypto/api/hash/hasher.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

struct ue_hasher {
	EVP_MD_CTX *md_ctx;
	const EVP_MD *type;
};

ue_hasher *ue_hasher_create() {
	ue_hasher *h;

	ue_safe_alloc(h, ue_hasher, 1);
	h->md_ctx = NULL;

	return h;
}

void ue_hasher_destroy(ue_hasher *h) {
	if (h) {
		EVP_MD_CTX_destroy(h->md_ctx);
		ue_safe_free(h);
	}
}

bool ue_hasher_init(ue_hasher *h, const char *digest_name) {
	char *error_buffer;

	error_buffer = NULL;

	if ((h->md_ctx = EVP_MD_CTX_create()) == NULL) {
		ue_openssl_error_handling(error_buffer, "Initialisation of message digest context");
		return false;
	}

    if (!(h->type = EVP_get_digestbyname(digest_name))) {
        ue_openssl_error_handling(error_buffer, "Digest wasn't found");
        return false;
    }

	return true;
}

static unsigned char *build_digest(ue_hasher *h, const unsigned char *message, size_t message_len, unsigned int *digest_len) {
	char *error_buffer;
	unsigned char *digest;

	error_buffer = NULL;
	digest = NULL;

	if (EVP_DigestInit_ex(h->md_ctx, h->type, NULL) != 1) {
		ue_openssl_error_handling(error_buffer, "Initialisation of message digest function");
		return NULL;
	}

	if (EVP_DigestUpdate(h->md_ctx, message, message_len) != 1) {
		ue_openssl_error_handling(error_buffer, "Digest update");
		return NULL;
	}

	if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(h->type))) == NULL) {
		ue_openssl_error_handling(error_buffer, "Allocation of digest string");
		return NULL;
	}

	if (EVP_DigestFinal_ex(h->md_ctx, digest, digest_len) != 1) {
		ue_openssl_error_handling(error_buffer, "Digest final step");
		return NULL;
	}

	return digest;
}

unsigned char *ue_hasher_digest(ue_hasher *h, const unsigned char *message, size_t message_len, size_t *digest_len) {
	unsigned char *digest;
	unsigned int digest_len_tmp;

    if (!(digest = build_digest(h, message, message_len, &digest_len_tmp))) {
        ue_stacktrace_push_msg("Failed to build digest");
        return NULL;
    }
	*digest_len = (size_t)digest_len_tmp;

	return digest;
}

int ue_hasher_get_digest_size(ue_hasher *h) {
	return EVP_MD_size(h->type);
}
