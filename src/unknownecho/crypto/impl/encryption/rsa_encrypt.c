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

#include <unknownecho/crypto/impl/encryption/rsa_encrypt.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>

#include <string.h>
#include <openssl/err.h>

unsigned char *ue_rsa_public_encrypt(ue_public_key *pk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding) {
	char *error_buffer;
    unsigned char *ciphertext, *buffer;
    int rsa_size, padding_code;
	RSA *rsa_pk;

    ue_check_parameter_or_return(plaintext);

	if (strcmp(padding, "PKCS1-OAEP") == 0) {
		padding_code = RSA_PKCS1_OAEP_PADDING;
	} else if (strcmp(padding, "PKCS1") == 0) {
		padding_code = RSA_PKCS1_PADDING;
	} else {
		ue_stacktrace_push_msg("Unknown padding algorithm");
		return NULL;
	}

	rsa_pk = ue_public_key_get_rsa_impl(pk);
    rsa_size = RSA_size(rsa_pk);
	if (plaintext_len > rsa_size) {
		ue_stacktrace_push_msg("The plaintext size is > than the block size");
		return NULL;
	}

    ue_safe_alloc(ciphertext, unsigned char, rsa_size);
    error_buffer = NULL;
    ue_safe_alloc(buffer, unsigned char, plaintext_len);
    memcpy(buffer, plaintext, plaintext_len * sizeof(unsigned char));

    if ((*ciphertext_len = RSA_public_encrypt(plaintext_len, buffer, ciphertext, rsa_pk, padding_code)) == -1) {
		ue_safe_alloc(error_buffer, char, 130);
		ERR_error_string(ERR_get_error(), error_buffer);
		ue_stacktrace_push_msg(error_buffer);
		ue_safe_free(error_buffer);
		ue_safe_free(ciphertext);
		ue_safe_free(buffer);
		RSA_free(rsa_pk);
		return NULL;
    }

	ue_safe_free(buffer);
	RSA_free(rsa_pk);

	return ciphertext;
}

unsigned char *ue_rsa_private_decrypt(ue_private_key *sk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding) {
	char *error_buffer;
    unsigned char *plaintext;
	RSA *rsa_sk;
	int padding_code;

    ue_check_parameter_or_return(ciphertext);

	if (strcmp(padding, "PKCS1-OAEP") == 0) {
		padding_code = RSA_PKCS1_OAEP_PADDING;
	} else if (strcmp(padding, "PKCS1") == 0) {
		padding_code = RSA_PKCS1_PADDING;
	} else {
		ue_stacktrace_push_msg("Unknown padding algorithm");
		return NULL;
	}

	rsa_sk = ue_private_key_get_rsa_impl(sk);

    ue_safe_alloc(plaintext, unsigned char, ciphertext_len);
    error_buffer = NULL;

    if ((*plaintext_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa_sk, padding_code)) == -1) {
    	ue_safe_alloc(error_buffer, char, 130);
        ERR_error_string(ERR_get_error(), error_buffer);
        ue_stacktrace_push_msg(error_buffer);
        ue_safe_free(error_buffer);
        ue_safe_free(plaintext);
		RSA_free(rsa_sk);
		return NULL;
    }

	RSA_free(rsa_sk);

    return plaintext;
}

unsigned char *ue_rsa_private_encrypt(ue_private_key *sk, unsigned char *plaintext, int plaintext_len, int *ciphertext_len, const char *padding) {
	char *error_buffer;
    unsigned char *ciphertext, *buffer;
    int rsa_size, padding_code;
	RSA *rsa_sk;

    ue_check_parameter_or_return(plaintext);

	if (strcmp(padding, "PKCS1-OAEP") == 0) {
		padding_code = RSA_PKCS1_OAEP_PADDING;
	} else if (strcmp(padding, "PKCS1") == 0) {
		padding_code = RSA_PKCS1_PADDING;
	} else {
		ue_stacktrace_push_msg("Unknown padding algorithm");
		return NULL;
	}

	if (!(rsa_sk = ue_private_key_get_rsa_impl(sk))) {
		ue_stacktrace_push_msg("Failed to get RSA implementation of specified private key");
		return NULL;
	}
    rsa_size = RSA_size(rsa_sk);
	if (plaintext_len > rsa_size) {
		ue_stacktrace_push_msg("The plaintext size is > than the block size");
		return NULL;
	}

    ue_safe_alloc(ciphertext, unsigned char, rsa_size);
    error_buffer = NULL;
    ue_safe_alloc(buffer, unsigned char, plaintext_len);
    memcpy(buffer, plaintext, plaintext_len * sizeof(unsigned char));

    if ((*ciphertext_len = RSA_private_encrypt(plaintext_len, buffer, ciphertext, rsa_sk, padding_code)) == -1) {
		ue_safe_alloc(error_buffer, char, 130);
		ERR_error_string(ERR_get_error(), error_buffer);
		ue_stacktrace_push_msg(error_buffer);
		ue_safe_free(error_buffer);
		ue_safe_free(ciphertext);
		ue_safe_free(buffer);
		RSA_free(rsa_sk);
		return NULL;
    }

    ue_safe_free(buffer);
	RSA_free(rsa_sk);

    return ciphertext;
}

unsigned char *ue_rsa_public_decrypt(ue_public_key *pk, unsigned char *ciphertext, int ciphertext_len, int *plaintext_len, const char *padding) {
	char *error_buffer;
    unsigned char *plaintext;
	RSA *rsa_pk;
	int padding_code;

    ue_check_parameter_or_return(ciphertext);

	if (strcmp(padding, "PKCS1-OAEP") == 0) {
		padding_code = RSA_PKCS1_OAEP_PADDING;
	} else if (strcmp(padding, "PKCS1") == 0) {
		padding_code = RSA_PKCS1_PADDING;
	} else {
		ue_stacktrace_push_msg("Unknown padding algorithm");
		return NULL;
	}

	rsa_pk = ue_public_key_get_rsa_impl(pk);

    ue_safe_alloc(plaintext, unsigned char, ciphertext_len);
    error_buffer = NULL;

    if ((*plaintext_len = RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, rsa_pk, padding_code)) == -1) {
    	ue_safe_alloc(error_buffer, char, 130);
        ERR_error_string(ERR_get_error(), error_buffer);
        ue_stacktrace_push_msg(error_buffer);
        ue_safe_free(error_buffer);
        ue_safe_free(plaintext);
		RSA_free(rsa_pk);
		return NULL;
    }

	RSA_free(rsa_pk);

    return plaintext;
}
