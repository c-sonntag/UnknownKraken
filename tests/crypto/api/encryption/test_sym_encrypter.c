#include "crypto/api/encryption/test_sym_encrypter.h"

#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

typedef struct {
	ue_sym_encrypter *encrypter;
	unsigned char *iv, *plaintext, *ciphertext, *deciphertext;
	size_t iv_size, plaintext_size, ciphertext_size, deciphertext_size;
} test_sym_encrypter_state;

void test_sym_encrypter(void **state) {
	test_sym_encrypter_state *test_state;
	bool allocated;

	test_state = *state;
	allocated = false;

	assert_non_null(test_state->encrypter = ue_sym_encrypter_default_create(ue_sym_key_create_random()));

	assert_int_not_equal(test_state->iv_size = ue_sym_encrypter_get_iv_size(test_state->encrypter), -1);

	ue_safe_alloc_ret(test_state->iv, unsigned char, test_state->iv_size, allocated)

	assert_true(allocated);

	assert_true(ue_crypto_random_bytes(test_state->iv, test_state->iv_size));

	assert_non_null(test_state->plaintext = ue_bytes_create_from_string("saluuuuuuuuut !"));

	assert_true((test_state->plaintext_size = strlen("saluuuuuuuuut !")) > 0);

	assert_non_null(test_state->ciphertext = ue_sym_encrypter_encrypt(test_state->encrypter, test_state->plaintext, test_state->plaintext_size, test_state->iv, test_state->iv_size, &test_state->ciphertext_size));

	assert_false(memcmp(test_state->plaintext, test_state->ciphertext, test_state->plaintext_size) == 0);

	assert_non_null(test_state->deciphertext = ue_sym_encrypter_decrypt(test_state->encrypter, test_state->ciphertext, test_state->ciphertext_size, test_state->iv, test_state->iv_size, &test_state->deciphertext_size));

	assert_true(memcmp(test_state->plaintext, test_state->deciphertext, test_state->plaintext_size) == 0);
}

int test_sym_encrypter_setup(void **state) {
	bool allocated;
	test_sym_encrypter_state *test_state;

	allocated = false;

	ue_safe_alloc_ret(test_state, test_sym_encrypter_state, 1, allocated)

	assert_true(allocated);

	test_state->encrypter = NULL;
	test_state->iv = NULL;
	test_state->plaintext = NULL;
	test_state->ciphertext = NULL;
	test_state->deciphertext = NULL;
	test_state->iv_size = -1;
	test_state->plaintext_size = -1;
	test_state->ciphertext_size = -1;
	test_state->deciphertext_size = -1;

	*state = test_state;

	return 0;
}

int test_sym_encrypter_teardown(void **state) {
	test_sym_encrypter_state *test_state;

	assert_non_null(*state);

	test_state = *state;

	ue_sym_encrypter_destroy(test_state->encrypter);
	ue_safe_free(test_state->iv)
	ue_safe_free(test_state->plaintext)
	ue_safe_free(test_state->ciphertext)
	ue_safe_free(test_state->deciphertext)

	ue_safe_free(*state)

	return 0;
}
