#include "crypto/api/encryption/test_asym_encrypter.h"

#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>

typedef struct {
	ue_asym_encrypter *encrypter;
	ue_asym_key *akey;
	unsigned char *plaintext, *ciphertext, *deciphertext;
	size_t plaintext_size, ciphertext_size, deciphertext_size;
} test_asym_encrypter_state;

void test_asym_encrypter(void **state) {
	test_asym_encrypter_state *test_state;

	test_state = *state;

	printf("main\n");

	assert_non_null(test_state->encrypter = ue_asym_encrypter_rsa_pkcs1_create(test_state->akey->pk, test_state->akey->sk));

	assert_non_null(test_state->ciphertext = ue_asym_encrypter_public_encrypt(test_state->encrypter, test_state->plaintext, test_state->plaintext_size, &test_state->ciphertext_size));

	assert_false(memcmp(test_state->plaintext, test_state->ciphertext, test_state->plaintext_size) == 0);

	assert_non_null(test_state->deciphertext = ue_asym_encrypter_private_decrypt(test_state->encrypter, test_state->ciphertext, test_state->ciphertext_size, &test_state->deciphertext_size));

	assert_true(memcmp(test_state->plaintext, test_state->deciphertext, test_state->plaintext_size) == 0);
}

int test_asym_encrypter_setup(void **state) {
	bool allocated;
	test_asym_encrypter_state *test_state;

	printf("setup\n");

	allocated = false;

	ue_safe_alloc_ret(test_state, test_asym_encrypter_state, 1, allocated)

	assert_true(allocated);

	test_state->encrypter = NULL;
	test_state->akey = ue_rsa_asym_key_create(2048);
	ue_asym_key_print(test_state->akey, stdout);
	test_state->plaintext = ue_bytes_create_from_string("Hello world !");
	test_state->ciphertext = NULL;
	test_state->deciphertext = NULL;
	test_state->plaintext_size = strlen("Hello world !");
	test_state->ciphertext_size = -1;
	test_state->deciphertext_size = -1;

	*state = test_state;

	return 0;
}

int test_asym_encrypter_teardown(void **state) {
	test_asym_encrypter_state *test_state;

	assert_non_null(*state);

	printf("teardown\n");

	test_state = *state;

	ue_asym_encrypter_destroy(test_state->encrypter);
	ue_asym_key_destroy_all(test_state->akey);
	ue_safe_free(test_state->plaintext)
	ue_safe_free(test_state->ciphertext)
	ue_safe_free(test_state->deciphertext)

	ue_safe_free(*state)

	if (ue_stacktrace_is_filled()) {
		ue_logger_info("Stacktrace is filled : ");
		ue_stacktrace_print();
		ue_stacktrace_clean_up();
	}

	return 0;
}
