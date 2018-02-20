#include <unknownecho/crypto/api/key/sym_key.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>

#define SYM_KEY_MIN_SIZE 32

ue_sym_key *ue_sym_key_create(unsigned char *data, size_t size) {
	ue_sym_key *key;

	ue_check_parameter_or_return(data);
	ue_check_parameter_or_return(size);

	if (size < SYM_KEY_MIN_SIZE) {
		ue_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
		return NULL;
	}

	ue_safe_alloc(key, ue_sym_key, 1);
	key->data = ue_bytes_create_from_bytes(data, size);
	key->size = size;

	return key;
}

void ue_sym_key_destroy(ue_sym_key *key) {
	if (key) {
		ue_safe_free(key->data);
		ue_safe_free(key);
	}
}

size_t ue_sym_key_get_min_size() {
	return SYM_KEY_MIN_SIZE;
}

bool ue_sym_key_is_valid(ue_sym_key *key) {
	ue_check_parameter_or_return(key);
	ue_check_parameter_or_return(key->data);

	if (key->size < SYM_KEY_MIN_SIZE) {
		ue_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
		return false;
	}

	return true;
}
