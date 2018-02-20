#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_encrypter *encrypter;

	encrypter = ue_asym_encrypter_create();
	ue_asym_encrypter_init(encrypter, "RSA-PKCS1");
	if (pk) {
		ue_asym_encrypter_set_pk(encrypter, pk);
	}
	if (sk) {
		ue_asym_encrypter_set_sk(encrypter, sk);
	}

	return encrypter;
}

ue_asym_encrypter *ue_asym_encrypter_rsa_pkcs1_oaep_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_encrypter *encrypter;

	encrypter = ue_asym_encrypter_create();
	ue_asym_encrypter_init(encrypter, "RSA-PKCS1-OAEP");
	if (pk) {
		ue_asym_encrypter_set_pk(encrypter, pk);
	}
	if (sk) {
		ue_asym_encrypter_set_sk(encrypter, sk);
	}

	return encrypter;
}

ue_asym_encrypter *ue_asym_encrypter_default_create(ue_public_key *pk, ue_private_key *sk) {
	return ue_asym_encrypter_rsa_pkcs1_oaep_create(pk, sk);
}
