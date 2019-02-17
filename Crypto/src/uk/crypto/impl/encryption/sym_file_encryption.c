/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/crypto/api/encryption/sym_file_encryption.h>
#include <uk/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/utils/ei.h>

#include <openssl/evp.h>

#include <stdio.h>

static bool evp_cipher_file(int should_encrypt, const EVP_CIPHER *cipher, const char *input_file_name, const char *output_file_name,
    unsigned char *key, unsigned char *iv);

bool uk_crypto_file_encrypt(const char *input_file_name, const char *output_file_name, uk_crypto_sym_key *key, unsigned char **iv, size_t *iv_size) {
    const EVP_CIPHER *cipher;
    int iv_length;
    unsigned char *teuk_mp_iv;
    
    if (!uk_crypto_sym_key_is_valid(key)) {
        uk_utils_stacktrace_push_msg("Specified sym key isn't valid");
        return false;
    }

    cipher = EVP_aes_256_cbc();
    iv_length = EVP_CIPHER_iv_length(cipher);
    *iv_size = (size_t)iv_length;
    teuk_mp_iv = NULL;
    uk_utils_safe_alloc(teuk_mp_iv, unsigned char, *iv_size);

    if (!uk_crypto_crypto_random_bytes(teuk_mp_iv, *iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to generate crypto random bytes for IV");
        uk_utils_safe_free(teuk_mp_iv);
        return false;
    }

    if (!evp_cipher_file(1, cipher, input_file_name, output_file_name, key->data, teuk_mp_iv)) {
        uk_utils_stacktrace_push_msg("Failed to process file encryption");
        uk_utils_safe_free(teuk_mp_iv);
        return false;
    }

    *iv = teuk_mp_iv;

    return true;
}

bool uk_crypto_file_decrypt(const char *input_file_name, const char *output_file_name, uk_crypto_sym_key *key, unsigned char *iv) {
    const EVP_CIPHER *cipher;
    
    if (!uk_crypto_sym_key_is_valid(key)) {
        uk_utils_stacktrace_push_msg("Specified sym key isn't valid");
        return false;
    }

    cipher = EVP_aes_256_cbc();

    if (!evp_cipher_file(0, cipher, input_file_name, output_file_name, key->data, iv)) {
        uk_utils_stacktrace_push_msg("Failed to process file decryption");
        return false;
    }

    return true;
}

static bool evp_cipher_file(int should_encrypt, const EVP_CIPHER *cipher, const char *input_file_name, const char *output_file_name,
    unsigned char *key, unsigned char *iv) {

    bool result;
    FILE *input_file, *output_file;
    EVP_CIPHER_CTX *ctx;
    unsigned short int CHUNK_SIZE;
    unsigned char *read_chunk, *cipher_chunk;
    unsigned block_size;
    int out_len;
    char *error_buffer;
    size_t read_size;

    uk_utils_check_parameter_or_return(cipher);
    uk_utils_check_parameter_or_return(input_file_name);
    uk_utils_check_parameter_or_return(output_file_name);
    uk_utils_check_parameter_or_return(key);
    uk_utils_check_parameter_or_return(iv);

    result = false;
    ctx = NULL;
    input_file = NULL;
    output_file = NULL;
    CHUNK_SIZE = 4096;
    read_chunk = NULL;
    cipher_chunk = NULL;
    error_buffer = NULL;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        uk_crypto_openssl_error_handling(error_buffer, "Cannot create new cipher context");
        return false;
    }

    if ((input_file = fopen(input_file_name, "rb")) == NULL) {
        uk_utils_stacktrace_push_errno();
        goto clean_up;
    }

    if ((output_file = fopen(output_file_name, "wb")) == NULL) {
        uk_utils_stacktrace_push_errno();
        goto clean_up;
    }

    uk_utils_safe_alloc_or_goto(read_chunk, unsigned char, CHUNK_SIZE, clean_up);

    if (!EVP_CipherInit(ctx, cipher, key, iv, should_encrypt)) {
        uk_crypto_openssl_error_handling(error_buffer, "Cannot init cipher context");
        goto clean_up;
    }

    /* Get the block size of the this cipher, depending of the cipher type setted in EVP_CipherInit() */
    block_size = EVP_CIPHER_CTX_block_size(ctx);

    uk_utils_safe_alloc_or_goto(cipher_chunk, unsigned char, CHUNK_SIZE + block_size, clean_up);

    /* Read in data in blocks until EOF. Update the ciphering with each read. */
    while (1) {
        /* Read a chunk of size CHUNK_SIZE and check if an error occurred */
        errno = 0;
        read_size = fread(read_chunk, sizeof(unsigned char), CHUNK_SIZE, input_file);
        if (errno != 0) {
            uk_utils_stacktrace_push_msg("Failed to read plain chunk with error message: %s", strerror(errno));
            goto clean_up;
        }

        /* Cipher the chunk */
        if (!EVP_CipherUpdate(ctx, cipher_chunk, &out_len, read_chunk, read_size)) {
            uk_crypto_openssl_error_handling(error_buffer, "Cannot update cipher context");
            goto clean_up;
        }

        /* Write the cipher chunk to the output file and check if an error occurred */
        errno = 0;
        fwrite(cipher_chunk, sizeof(unsigned char), out_len, output_file);
        if (errno != 0) {
            uk_utils_stacktrace_push_msg("Failed to write cipher chunk with error message: %s", strerror(errno));
            goto clean_up;
        }

        /**
         * If read_size is < CHUNK_SIZE, the input file was complete
         * encrypted/decrypted. If read_size is equal to 0, then EVP_CipherFinal()
         * will cipher the remains bytes.
         */
        if (read_size < CHUNK_SIZE) {
            break;
        }
    }

    /* Cipher the last chunk */
    if (!EVP_CipherFinal(ctx, cipher_chunk, &out_len)) {
        uk_crypto_openssl_error_handling(error_buffer, "Cannot process the last chunk of cipher context");
        goto clean_up;
    }

    /* Write the last chunk */
    errno = 0;
    fwrite(cipher_chunk, sizeof(unsigned char), out_len, output_file);
    if (errno != 0) {
        uk_utils_stacktrace_push_msg("Failed to write the last cipher chunk with error message: %s", strerror(errno));
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(read_chunk);
    uk_utils_safe_free(cipher_chunk);
    uk_utils_safe_fclose(input_file);
    uk_utils_safe_fclose(output_file);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
