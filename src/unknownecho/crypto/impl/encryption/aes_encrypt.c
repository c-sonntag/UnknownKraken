#include <unknownecho/crypto/impl/encryption/aes_encrypt.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

bool ue_aes_encrypt_256_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len) {

	int len, rlen;
	EVP_CIPHER_CTX *ctx;
	char *error_buffer;

	error_buffer = NULL;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ue_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
		return false;
	}

	/**
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_EncryptInit_ex");
		return false;
	}

	/**
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_EncryptUpdate");
		return false;
	}

	*ciphertext_len = len;

	/**
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &rlen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_EncryptFinal_ex");
		return false;
	}

	*ciphertext_len += rlen;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return true;
}

int ue_aes_decrypt_256_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext, int *plaintext_len) {

	EVP_CIPHER_CTX *ctx;
	int len, rlen;
	char *error_buffer;

	error_buffer = NULL;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		ue_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
		return false;
	}

	/**
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_DecryptInit_ex");
		return false;
	}

	/**
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_DecryptUpdate");
		return false;
	}

	*plaintext_len = len;

	/**
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &rlen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		ue_openssl_error_handling(error_buffer, "EVP_DecryptFinal_ex");
		return false;
	}

	*plaintext_len += rlen;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return true;
}
