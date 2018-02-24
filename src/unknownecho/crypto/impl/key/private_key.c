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

#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct ue_private_key {
	ue_private_key_type type;
	EVP_PKEY *impl;
	int bits;
};

ue_private_key *ue_private_key_create_from_impl(void *impl) {
	EVP_PKEY *key_impl;
	RSA *rsa;
	ue_private_key *sk;

	key_impl = (EVP_PKEY *)impl;
	if (EVP_PKEY_base_id(key_impl) == EVP_PKEY_RSA) {
		rsa = EVP_PKEY_get1_RSA(key_impl);
		sk = ue_private_key_create(RSA_PRIVATE_KEY, rsa, RSA_size(rsa));
		RSA_free(rsa);
		return sk;
	} else {
		ue_stacktrace_push_msg("Specified key type is not supported");
	}

	return NULL;
}

ue_private_key *ue_private_key_create(ue_private_key_type key_type, void *impl, int bits) {
	ue_private_key *sk;

	ue_safe_alloc(sk, ue_private_key, 1);

	sk->impl = EVP_PKEY_new();

	if (key_type == RSA_PRIVATE_KEY) {
		EVP_PKEY_set1_RSA(sk->impl, (RSA *)impl);
		sk->type = RSA_PRIVATE_KEY;
	} else {
		ue_private_key_destroy(sk);
		ue_stacktrace_push_msg("Specified key type is unknown");
		return NULL;
	}

	sk->bits = bits;

	if (!ue_private_key_is_valid(sk)) {
		ue_private_key_destroy(sk);
		return NULL;
	}

	return sk;
}

void ue_private_key_destroy(ue_private_key *sk) {
	if (sk) {
		if (sk->impl) {
			EVP_PKEY_free(sk->impl);
		}
		ue_safe_free(sk);
	}
}

int ue_private_key_size(ue_private_key *sk) {
	if (sk->type == RSA_PRIVATE_KEY) {
		return RSA_size((RSA *)sk->impl);
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return -1;
}

bool ue_private_key_is_valid(ue_private_key *sk) {
	return true;

	if (sk->type == RSA_PRIVATE_KEY) {
		return RSA_check_key(EVP_PKEY_get1_RSA(sk->impl)) && ue_private_key_size(sk) == sk->bits;
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return false;
}

void *ue_private_key_get_impl(ue_private_key *sk) {
	return sk->impl;
}

void *ue_private_key_get_rsa_impl(ue_private_key *sk) {
	if (!sk) {
		ue_stacktrace_push_msg("Specified private key ptr is null");
		return NULL;
	}

	if (!sk->impl) {
		ue_stacktrace_push_msg("This private key has no implementation");
		return NULL;
	}
	return EVP_PKEY_get1_RSA(sk->impl);
}

bool ue_private_key_print(ue_private_key *sk, FILE *out_fd) {
	char *error_buffer;

	error_buffer = NULL;

	if (PEM_write_PrivateKey(out_fd, sk->impl, NULL, NULL, 0, NULL, NULL) == 0) {
		ue_openssl_error_handling(error_buffer, "PEM_write_PrivateKey");
		return false;
	}

	return true;
}
