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

#include <unknownecho/crypto/impl/envelope/envelope_open.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <ei/ei.h>

bool envelope_open_buffer(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char **plaintext, int *plaintext_len, const char *cipher_name) {

    bool result;
	EVP_CIPHER_CTX *ctx;
	int len;
    const EVP_CIPHER *cipher;
    char *error_buffer;

	ei_check_parameter_or_return(priv_key);
	ei_check_parameter_or_return(ciphertext);
	ei_check_parameter_or_return(ciphertext_len > 0);
	ei_check_parameter_or_return(encrypted_key);
	ei_check_parameter_or_return(encrypted_key_len > 0);
	ei_check_parameter_or_return(cipher_name);

    result = NULL;
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

	if (EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, priv_key) != 1) {
        ue_openssl_error_handling(error_buffer, "Failed to init seal");
		goto clean_up;
    }

    ue_safe_alloc_or_goto(*plaintext, unsigned char, ciphertext_len + EVP_CIPHER_iv_length(cipher), clean_up);

	if (EVP_OpenUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        ue_openssl_error_handling(error_buffer, "EVP_SealUpdate");
		goto clean_up;
    }

	*plaintext_len = len;

	if (EVP_OpenFinal(ctx, *plaintext + len, &len) != 1) {
        ue_openssl_error_handling(error_buffer, "EVP_SealFinal");
		goto clean_up;
    }

	*plaintext_len += len;

    result = true;

clean_up:
	EVP_CIPHER_CTX_free(ctx);
	return result;
}
