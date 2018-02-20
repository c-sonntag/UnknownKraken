#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>

ue_asym_key *ue_asym_key_create(ue_public_key *pk, ue_private_key *sk) {
	ue_asym_key *akey;

	ue_safe_alloc(akey, ue_asym_key, 1)
	akey->pk = pk;
	akey->sk = sk;

	return akey;
}

void ue_asym_key_destroy(ue_asym_key *akey){
	ue_safe_free(akey);
}


void ue_asym_key_destroy_all(ue_asym_key *akey){
	if (akey) {
		ue_public_key_destroy(akey->pk);
		ue_private_key_destroy(akey->sk);
		ue_safe_free(akey);
	}
}

bool ue_asym_key_is_valid(ue_asym_key *akey){
	return akey && akey->pk && akey->sk &&
		ue_public_key_is_valid(akey->pk) &&
		ue_private_key_is_valid(akey->sk);
}

bool ue_asym_key_print(ue_asym_key *akey, FILE *out_fd) {
	if (!akey || !akey->pk || !akey->sk) {
		return false;
	}

	ue_public_key_print(akey->pk, out_fd);
	ue_private_key_print(akey->sk, out_fd);

	return true;
}
