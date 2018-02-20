#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/system/alloc.h>

#include <stddef.h>

ue_sym_key *ue_sym_key_create_random() {
	ue_sym_key *key;
	unsigned char *buf;
	size_t buf_size;

	key = NULL;
	buf_size = ue_sym_key_get_min_size();
	ue_safe_alloc(buf, unsigned char, buf_size);

	if (!ue_crypto_random_bytes(buf, buf_size)) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes");
		ue_safe_free(buf);
		return NULL;
	}

	key = ue_sym_key_create(buf, buf_size);

	ue_safe_free(buf);

	return key;
}

ue_sym_key *ue_sym_key_create_from_file(char *file_path) {
	ue_stacktrace_push_msg("Not implemented");
	return NULL;
}
