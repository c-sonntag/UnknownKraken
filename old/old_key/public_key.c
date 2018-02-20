#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>

typedef union {
	RSA *ue_rsa_pk;
} ue_public_key_impl;

struct ue_public_key {
	ue_public_key_type type;
	ue_public_key_impl impl;
	int bits;
};

ue_public_key *ue_public_key_create(ue_public_key_type key_type, void *impl, int bits) {
	ue_public_key *pk;

	if (key_type != RSA_PUBLIC_KEY) {
		ue_stacktrace_push_msg("Specified key type is unknown");
		return NULL;
	}

	ue_safe_alloc(pk, ue_public_key, 1);
	pk->impl.ue_rsa_pk = (RSA *)impl;
	pk->type = RSA_PUBLIC_KEY;
	pk->bits = bits;

	if (!ue_public_key_is_valid(pk)) {
		ue_public_key_destroy(pk);
		return NULL;
	}

	return pk;
}

void ue_public_key_destroy(ue_public_key *pk) {
	if (pk) {
		if (pk->type == RSA_PUBLIC_KEY) {
			RSA_free(pk->impl.ue_rsa_pk);
			pk->impl.ue_rsa_pk = NULL;
		}
		ue_safe_free(pk);
	}
}

static bool is_valid_rsa_public_key(RSA *pk) {
    /**
     * from ue_rsa_ameth.c do_rsa_print : has a public key
     * from ue_rsa_chk.c RSA_check_key : doesn't have n (modulus) and e (public exponent);
     */
    if (!pk || pk->d || !pk->n || !pk->e) {
        return false;
    }

    /**
     * from http://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=1454
     * doesnt have a valid public exponent
     */
    return BN_is_odd(pk->e) && !BN_is_one(pk->e);
}

int ue_public_key_size(ue_public_key *pk) {
	if (pk->type == RSA_PUBLIC_KEY) {
		return RSA_size(pk->impl.ue_rsa_pk);
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return -1;
}

bool ue_public_key_is_valid(ue_public_key *pk) {
	return true;

	if (pk->type == RSA_PUBLIC_KEY) {
		return is_valid_rsa_public_key(pk->impl.ue_rsa_pk) && ue_public_key_size(pk) == pk->bits;
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return false;
}

void *ue_public_key_get_impl(ue_public_key *pk) {
	return pk->impl.ue_rsa_pk;
}
