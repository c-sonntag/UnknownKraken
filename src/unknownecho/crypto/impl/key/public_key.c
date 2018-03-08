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

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct ue_public_key {
	ue_public_key_type type;
	EVP_PKEY *impl;
	int bits;
};

ue_public_key *ue_public_key_create(ue_public_key_type key_type, void *impl, int bits) {
	ue_public_key *pk;

	ue_safe_alloc(pk, ue_public_key, 1);

	pk->impl = EVP_PKEY_new();

	if (key_type == RSA_PUBLIC_KEY) {
		EVP_PKEY_set1_RSA(pk->impl, (RSA *)impl);
		pk->type = RSA_PUBLIC_KEY;
	} else {
		ue_public_key_destroy(pk);
		ue_stacktrace_push_msg("Specified key type is unknown");
		return NULL;
	}

	pk->bits = bits;

	if (!ue_public_key_is_valid(pk)) {
		ue_public_key_destroy(pk);
		return NULL;
	}

	return pk;
}

void ue_public_key_destroy(ue_public_key *pk) {
	if (pk) {
		if (pk->impl) {
			EVP_PKEY_free(pk->impl);
		}
		ue_safe_free(pk);
	}
}

static bool is_valid_rsa_public_key(RSA *pk) {
	const BIGNUM *n, *e, *d;

    /**
     * from ue_rsa_ameth.c do_rsa_print : has a public key
     * from ue_rsa_chk.c RSA_check_key : doesn't have n (modulus) and e (public exponent);
     */

	 RSA_get0_key(pk, &n, &e, &d);

    if (!pk || d || !e || !e) {
        return false;
    }

    /**
     * from http://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=1454
     * doesnt have a valid public exponent
     */
    return BN_is_odd(e) && !BN_is_one(e);
}

int ue_public_key_size(ue_public_key *pk) {
	if (pk->type == RSA_PUBLIC_KEY) {
		return RSA_size((RSA *)pk->impl);
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return -1;
}

bool ue_public_key_is_valid(ue_public_key *pk) {
	return true;

	if (pk->type == RSA_PUBLIC_KEY) {
		return is_valid_rsa_public_key(EVP_PKEY_get1_RSA(pk->impl)) && ue_public_key_size(pk) == pk->bits;
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return false;
}

void *ue_public_key_get_impl(ue_public_key *pk) {
	return pk->impl;
}

void *ue_public_key_get_rsa_impl(ue_public_key *pk) {
	if (!pk->impl) {
		ue_stacktrace_push_msg("Specified public key have no implementation");
		return NULL;
	}
	return EVP_PKEY_get1_RSA(pk->impl);
}

bool ue_public_key_print(ue_public_key *pk, FILE *out_fd) {
	RSA *rsa;

	rsa = NULL;

	if (EVP_PKEY_id(pk->impl) == EVP_PKEY_RSA) {
	    if (!(rsa = EVP_PKEY_get1_RSA(pk->impl))) {
			return false;
		}
	    RSA_print_fp(out_fd, rsa, 0);
	    RSA_free(rsa);
		return true;
	}

	return false;
}
