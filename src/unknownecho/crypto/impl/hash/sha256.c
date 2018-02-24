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

#include <unknownecho/crypto/impl/hash/sha256.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/evp.h>

bool ue_hash_sha256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len) {
	EVP_MD_CTX *md_ctx;
	char *error_buffer;

	error_buffer = NULL;

	if ((md_ctx = EVP_MD_CTX_create()) == NULL) {
		ue_openssl_error_handling(error_buffer, "Initialisation of message digest context");
		return false;
	}

	if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
		ue_openssl_error_handling(error_buffer, "Initialisation of message digest sha256 function");
		EVP_MD_CTX_destroy(md_ctx);
		return false;
	}

	if (EVP_DigestUpdate(md_ctx, message, message_len) != 1) {
		ue_openssl_error_handling(error_buffer, "Digest update");
		EVP_MD_CTX_destroy(md_ctx);
		return false;
	}

	if ((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL) {
		ue_openssl_error_handling(error_buffer, "Allocation of digest string");
		EVP_MD_CTX_destroy(md_ctx);
		return false;
	}

	if (EVP_DigestFinal_ex(md_ctx, *digest, digest_len) != 1) {
		ue_openssl_error_handling(error_buffer, "Digest final step");
		EVP_MD_CTX_destroy(md_ctx);
		return false;
	}

	EVP_MD_CTX_destroy(md_ctx);

	return true;
}
