#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <openssl/rsa.h>

typedef union {
	RSA *ue_rsa_sk;
} ue_private_key_impl;

struct ue_private_key {
	ue_private_key_type type;
	ue_private_key_impl impl;
	int bits;
};

ue_private_key *ue_private_key_create(ue_private_key_type key_type, void *impl, int bits) {
	ue_private_key *sk;

	if (key_type != RSA_PRIVATE_KEY) {
		ue_stacktrace_push_msg("Specified key type is unknown");
		return NULL;
	}

	ue_safe_alloc(sk, ue_private_key, 1);
	sk->impl.ue_rsa_sk = (RSA *)impl;
	sk->type = RSA_PRIVATE_KEY;
	sk->bits = bits;

	if (!ue_private_key_is_valid(sk)) {
		ue_private_key_destroy(sk);
		return NULL;
	}

	return sk;
}

void ue_private_key_destroy(ue_private_key *sk) {
	if (sk) {
		if (sk->type == RSA_PRIVATE_KEY) {
			RSA_free(sk->impl.ue_rsa_sk);
			sk->impl.ue_rsa_sk = NULL;
		}
		ue_safe_free(sk);
	}
}

int ue_private_key_size(ue_private_key *sk) {
	if (sk->type == RSA_PRIVATE_KEY) {
		return RSA_size(sk->impl.ue_rsa_sk);
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return -1;
}

bool ue_private_key_is_valid(ue_private_key *sk) {
	return true;

	if (sk->type == RSA_PRIVATE_KEY) {
		return RSA_check_key(sk->impl.ue_rsa_sk) && ue_private_key_size(sk) == sk->bits;
	}

	ue_stacktrace_push_msg("Not implemented key type");

	return false;
}

void *ue_private_key_get_impl(ue_private_key *sk) {
	return sk->impl.ue_rsa_sk;
}
