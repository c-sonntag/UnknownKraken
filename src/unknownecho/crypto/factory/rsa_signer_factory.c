#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/factory/hasher_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_signer *ue_rsa_signer_create(ue_public_key *pk, ue_private_key *sk) {
	ue_signer *s;

	if (!pk) {
		ue_stacktrace_push_msg("Specified public key is null");
		return NULL;
	}

	if (!sk) {
		ue_stacktrace_push_msg("Specified private key is null");
		return NULL;
	}

	if (!(s = ue_signer_create())) {
		ue_stacktrace_push_msg("Failed to create signer");
		return NULL;
	}

	if (!(s->encrypter = ue_asym_encrypter_rsa_pkcs1_create(pk, sk))) {
		ue_signer_destroy(s);
		ue_stacktrace_push_msg("Failed to create rsa pkcs1 asym encrypter from specified key(s)");
		return NULL;
	}

	if (!(s->h = ue_hasher_default_create())) {
		ue_signer_destroy(s);
		ue_stacktrace_push_msg("Failed to create default hasher");
		return NULL;
	}

	return s;
}

ue_signer *ue_rsa_signer_create_from_pair(ue_asym_key *akey) {
	ue_signer *s;

	s = ue_signer_create();

	s->encrypter = ue_asym_encrypter_rsa_pkcs1_create(akey->pk, akey->sk);

	s->h = ue_hasher_default_create();

	return s;
}
