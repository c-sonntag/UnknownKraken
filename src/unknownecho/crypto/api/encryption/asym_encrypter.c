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

#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/impl/encryption/rsa_encrypt.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/string/string_utility.h>

#include <string.h>

ue_asym_encrypter *ue_asym_encrypter_create() {
	ue_asym_encrypter *encrypter;

	ue_safe_alloc(encrypter, ue_asym_encrypter, 1);
	encrypter->algorithm = NULL;
	encrypter->pk = NULL;
	encrypter->sk = NULL;

	return encrypter;
}

void ue_asym_encrypter_destroy(ue_asym_encrypter *encrypter) {
	if (encrypter) {
		ue_safe_free(encrypter->algorithm);
		ue_safe_free(encrypter);
	}
}

void ue_asym_encrypter_destroy_all(ue_asym_encrypter *encrypter) {
	if (encrypter) {
		ue_public_key_destroy(encrypter->pk);
		ue_private_key_destroy(encrypter->sk);
		ue_safe_free(encrypter->algorithm);
		ue_safe_free(encrypter);
	}
}

bool ue_asym_encrypter_init(ue_asym_encrypter *encrypter, const char *algorithm) {
	if (strcmp(algorithm, "RSA-PKCS1-OAEP") != 0 &&
		strcmp(algorithm, "RSA-PKCS1") != 0) {

		ue_stacktrace_push_msg("Not implemented hash algorithm");
		return false;
	}

	encrypter->algorithm = ue_string_create_from(algorithm);

	return true;
}

bool ue_asym_encrypter_set_pk(ue_asym_encrypter *encrypter, ue_public_key *pk) {
	ue_check_parameter_or_return(encrypter);

	/*if (!ue_public_key_is_valid(key)) {
		ue_stacktrace_push_msg("Specified key is invalid");
		return false;
	}*/

	encrypter->pk = pk;

	return true;
}

bool ue_asym_encrypter_set_sk(ue_asym_encrypter *encrypter, ue_private_key *sk) {
	ue_check_parameter_or_return(encrypter);

	/*if (!ue_private_key_is_valid(key)) {
		ue_stacktrace_push_msg("Specified key is invalid");
		return false;
	}*/

	encrypter->sk = sk;

	return true;
}

unsigned char *ue_asym_encrypter_public_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size) {
	unsigned char *ciphertext;
	int ciphertext_len;

	ue_check_parameter_or_return(plaintext);
	ue_check_parameter_or_return(plaintext_size != -1);

	if (strcmp(encrypter->algorithm, "RSA-PKCS1-OAEP") == 0) {
		ciphertext = ue_rsa_public_encrypt(encrypter->pk, plaintext, plaintext_size, &ciphertext_len, "PKCS1-OAEP");
	} else if (strcmp(encrypter->algorithm, "RSA-PKCS1") == 0) {
		ciphertext = ue_rsa_public_encrypt(encrypter->pk, plaintext, plaintext_size, &ciphertext_len, "PKCS1");
	} else {
		ue_stacktrace_push_msg("Unknown algorithm");
		return NULL;
	}

	*ciphered_text_size = ciphertext_len;

	return ciphertext;
}

unsigned char *ue_asym_encrypter_private_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size) {
	unsigned char *plaintext;
	int plaintext_len;

	ue_check_parameter_or_return(ciphered_text);
	ue_check_parameter_or_return(ciphered_text_size != -1);

	if (strcmp(encrypter->algorithm, "RSA-PKCS1-OAEP") == 0) {
		plaintext = ue_rsa_private_decrypt(encrypter->sk, ciphered_text, ciphered_text_size, &plaintext_len, "PKCS1-OAEP");
	} else if (strcmp(encrypter->algorithm, "RSA-PKCS1") == 0) {
		plaintext = ue_rsa_private_decrypt(encrypter->sk, ciphered_text, ciphered_text_size, &plaintext_len, "PKCS1");
	} else {
		ue_stacktrace_push_msg("Unknown algorithm");
		return NULL;
	}

	*plaintext_size = plaintext_len;

	return plaintext;
}

unsigned char *ue_asym_encrypter_private_encrypt(ue_asym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, size_t *ciphered_text_size) {
	unsigned char *ciphertext;
	int ciphertext_len;

	ue_check_parameter_or_return(plaintext);
	ue_check_parameter_or_return(plaintext_size != -1);

	if (strcmp(encrypter->algorithm, "RSA-PKCS1-OAEP") == 0) {
		ciphertext = ue_rsa_private_encrypt(encrypter->sk, plaintext, plaintext_size, &ciphertext_len, "PKCS1-OAEP");
	} else if (strcmp(encrypter->algorithm, "RSA-PKCS1") == 0) {
		ciphertext = ue_rsa_private_encrypt(encrypter->sk, plaintext, plaintext_size, &ciphertext_len, "PKCS1");
	} else {
		ue_stacktrace_push_msg("Unknown algorithm");
		return NULL;
	}

	*ciphered_text_size = ciphertext_len;

	return ciphertext;
}

unsigned char *ue_asym_encrypter_public_decrypt(ue_asym_encrypter *encrypter, unsigned char *ciphered_text, size_t ciphered_text_size, size_t *plaintext_size) {
	unsigned char *plaintext;
	int plaintext_len;

	ue_check_parameter_or_return(ciphered_text);
	ue_check_parameter_or_return(ciphered_text_size != -1);

	if (strcmp(encrypter->algorithm, "RSA-PKCS1-OAEP") == 0) {
		plaintext = ue_rsa_public_decrypt(encrypter->pk, ciphered_text, ciphered_text_size, &plaintext_len, "PKCS1-OAEP");
	} else if (strcmp(encrypter->algorithm, "RSA-PKCS1") == 0) {
		plaintext = ue_rsa_public_decrypt(encrypter->pk, ciphered_text, ciphered_text_size, &plaintext_len, "PKCS1");
	} else {
		ue_stacktrace_push_msg("Unknown algorithm");
		return NULL;
	}

	*plaintext_size = plaintext_len;

	return plaintext;
}
