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

#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/impl/encryption/aes_encrypt.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>

ue_sym_encrypter *ue_sym_encrypter_create() {
	ue_sym_encrypter *encrypter;

	ue_safe_alloc(encrypter, ue_sym_encrypter, 1);
	encrypter->key = NULL;

	return encrypter;
}

void ue_sym_encrypter_destroy(ue_sym_encrypter *encrypter) {
	if (encrypter) {
		ue_safe_free(encrypter);
	}
}

void ue_sym_encrypter_destroy_all(ue_sym_encrypter *encrypter) {
	if (encrypter) {
		ue_sym_key_destroy(encrypter->key);
		ue_safe_free(encrypter);
	}
}

bool ue_sym_encrypter_set_key(ue_sym_encrypter *encrypter, ue_sym_key *key) {
	ue_check_parameter_or_return(encrypter);

	if (!ue_sym_key_is_valid(key)) {
		ue_stacktrace_push_msg("Specified key is invalid");
		return false;
	}

	encrypter->key = key;

	return true;
}

size_t ue_sym_encrypter_get_iv_size(ue_sym_encrypter *encrypter) {
	if (encrypter->type == AES && encrypter->mode == AES_CBC) {
		if (encrypter->key_size == 32) {
			return 16;
		}
	}

	return -1;
}

unsigned char *ue_sym_encrypter_encrypt(ue_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size,
	unsigned char *iv, unsigned int iv_size, size_t *ciphertext_size) {

	int aes_tmp_ciphertext_len;
	unsigned char *ciphertext;

	ue_check_parameter_or_return(encrypter);
	ue_check_parameter_or_return(plaintext);
	ue_check_parameter_or_return(plaintext_size > 0);
	ue_check_parameter_or_return(iv);
	ue_check_parameter_or_return(iv_size > 0);

	ciphertext = NULL;
	*ciphertext_size = 0;

	if (encrypter->type == AES && encrypter->mode != AES_CBC) {
		ue_stacktrace_push_msg("Algorithm type and mode are not compatible with bloc cipher encryption");
		return NULL;
	}

	if (encrypter->iv_size != iv_size) {
		ue_stacktrace_push_msg("Specified IV size is %ld but encrypter IV size is %ld", iv_size * 8, encrypter->iv_size);
		return NULL;
	}

	if (encrypter->mode == AES_CBC) {
		if (encrypter->key_size == 32 && encrypter->iv_size == 16) {
			ue_safe_alloc(ciphertext, unsigned char, plaintext_size * 2);
			if (ue_aes_encrypt_256_cbc(plaintext, (int)plaintext_size, encrypter->key->data, iv, ciphertext, &aes_tmp_ciphertext_len)) {
				*ciphertext_size = aes_tmp_ciphertext_len;
				ue_safe_realloc(ciphertext, unsigned char, plaintext_size * 2, (plaintext_size * 2) - *ciphertext_size);
			} else {
				ue_stacktrace_push_msg("Failed to encrypt with AES-256CBC");
				ue_safe_free(ciphertext);
				return NULL;
			}
		} else {
			ue_stacktrace_push_msg("Combinaison of encrypter key size %ld and encrypter IV size %ld is incompatible", encrypter->key_size, encrypter->iv_size);
			return NULL;
		}
	} else {
		ue_stacktrace_push_msg("Not implemented encryption mode for bloc cipher algorithm");
		return NULL;
	}

	return ciphertext;
}

unsigned char *ue_sym_encrypter_decrypt(ue_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size,
	unsigned char *iv, unsigned int iv_size, size_t *plaintext_size) {

	int aes_tmp_ciphertext_len;
	unsigned char *plaintext;

	ue_check_parameter_or_return(encrypter);
	ue_check_parameter_or_return(ciphertext);
	ue_check_parameter_or_return(ciphertext_size > 0);
	ue_check_parameter_or_return(iv);
	ue_check_parameter_or_return(iv_size > 0);

	plaintext = NULL;
	*plaintext_size = 0;

	if (encrypter->type == AES && encrypter->mode != AES_CBC) {
		ue_stacktrace_push_msg("Algorithm type and mode are not compatible with bloc cipher encryption");
		return NULL;
	}

	if (encrypter->iv_size != iv_size) {
		ue_stacktrace_push_msg("Specified IV size is %d but encrypter IV size is %ld", iv_size * 8, encrypter->iv_size);
		return NULL;
	}

	if (encrypter->mode == AES_CBC) {
		if (encrypter->key_size == 32 && encrypter->iv_size == 16) {
			ue_safe_alloc(plaintext, unsigned char, ciphertext_size * 2);
			if (ue_aes_decrypt_256_cbc(ciphertext, (int)ciphertext_size, encrypter->key->data, iv, plaintext, &aes_tmp_ciphertext_len)) {
				*plaintext_size = aes_tmp_ciphertext_len;
				ue_safe_realloc(plaintext, unsigned char, ciphertext_size * 2, (ciphertext_size * 2) - *plaintext_size);
			} else {
				ue_stacktrace_push_msg("Failed to decrypt with AES-256CBC");
				ue_safe_free(plaintext);
				return NULL;
			}
		} else {
			ue_stacktrace_push_msg("Combinaison of encrypter key size %ld and encrypter IV size %ld is incompatible", encrypter->key_size, encrypter->iv_size);
			return NULL;
		}
	} else {
		ue_stacktrace_push_msg("Not implemented encryption mode for bloc cipher algorithm");
		return NULL;
	}

	return plaintext;
}
