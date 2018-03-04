#include <unknownecho/crypto/impl/envelope/envelope_open.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

bool envelope_open_buffer(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char **plaintext, int *plaintext_len, const char *cipher_name) {

    bool result;
	EVP_CIPHER_CTX *ctx;
	int len;
    const EVP_CIPHER *cipher;
    char *error_buffer;

    result = NULL;
    ctx = NULL;
    error_buffer = NULL;

    if (!(cipher = EVP_get_cipherbyname(cipher_name))) {
		ue_openssl_error_handling(error_buffer, "Invalid cipher name");
		goto clean_up;
	}

    if (!(ctx = EVP_CIPHER_CTX_new())) {
		ue_openssl_error_handling(error_buffer, "Failed to create new cipher");
        goto clean_up;
    }

	if (EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, priv_key) != 1) {
        ue_openssl_error_handling(error_buffer, "Failed to init seal");
		goto clean_up;
    }

    ue_safe_alloc_or_goto(*plaintext, unsigned char, ciphertext_len + EVP_CIPHER_iv_length(cipher), clean_up);

	if (EVP_OpenUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1) {
        ue_openssl_error_handling(error_buffer, "EVP_SealUpdate");
		goto clean_up;
    }

	*plaintext_len = len;

	if (EVP_OpenFinal(ctx, *plaintext + len, &len) != 1) {
        ue_openssl_error_handling(error_buffer, "EVP_SealFinal");
		goto clean_up;
    }

	*plaintext_len += len;

    result = true;

clean_up:
	EVP_CIPHER_CTX_free(ctx);
	return result;
}
