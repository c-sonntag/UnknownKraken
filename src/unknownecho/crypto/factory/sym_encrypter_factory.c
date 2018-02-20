#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>

ue_sym_encrypter *ue_sym_encrypter_aes_create(ue_sym_key *key) {
	ue_sym_encrypter *encrypter;

	if (!ue_sym_key_is_valid(key)) {
		ue_stacktrace_push_msg("Specified key is invalid");
		return NULL;
	}

	if (key->size < ue_sym_key_get_min_size()) {
		ue_stacktrace_push_msg("Specified key size is invalid. %d bytes is required.", ue_sym_key_get_min_size());
		return NULL;
	}

	encrypter = ue_sym_encrypter_create();
	encrypter->type = AES;
	encrypter->mode = AES_CBC;
	encrypter->key_size = 32;
	encrypter->iv_size = 16;
	encrypter->key = key;

	return encrypter;
}

ue_sym_encrypter *ue_sym_encrypter_default_create(ue_sym_key *key) {
	return ue_sym_encrypter_aes_create(key);
}
