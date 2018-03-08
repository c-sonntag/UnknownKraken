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

#include <unknownecho/crypto/impl/envelope/envelope_seal.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

bool envelope_seal_buffer(EVP_PKEY *pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **encrypted_key, int *encrypted_key_len, unsigned char **iv, int *iv_len,
	unsigned char **ciphertext, int *ciphertext_len, const char *cipher_name) {

	bool result;
    EVP_CIPHER_CTX *ctx;
	int len;
	const EVP_CIPHER *cipher;
	char *error_buffer;

	result = false;
	ctx = NULL;
	error_buffer = NULL;

	if (!(cipher = EVP_get_cipherbyname(cipher_name))) {
		ue_openssl_error_handling(error_buffer, "Invalid cipher name");
		goto clean_up;
	}

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ue_openssl_error_handling(error_buffer, "Failed to create new cipher");
        goto clean_up;
    }

	*iv_len = EVP_CIPHER_iv_length(cipher);
    ue_safe_alloc_or_goto(*iv, unsigned char, *iv_len, clean_up);

	ue_safe_alloc_or_goto(*encrypted_key, unsigned char, EVP_PKEY_size(pub_key), clean_up);

	ue_safe_alloc_or_goto(*ciphertext, unsigned char, plaintext_len + *iv_len, clean_up);

	if (EVP_SealInit(ctx, cipher, encrypted_key, encrypted_key_len, *iv, &pub_key, 1) != 1) {
		ue_openssl_error_handling(error_buffer, "Failed to init seal");
		goto clean_up;
	}

	if (EVP_SealUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
		ue_openssl_error_handling(error_buffer, "EVP_SealUpdate");
		goto clean_up;
	}

	*ciphertext_len = len;

	if (EVP_SealFinal(ctx, *ciphertext + len, &len) != 1) {
		ue_openssl_error_handling(error_buffer, "EVP_SealFinal");
		goto clean_up;
	}

	*ciphertext_len += len;

	result = true;

clean_up:
	EVP_CIPHER_CTX_free(ctx);
	return result;
}
