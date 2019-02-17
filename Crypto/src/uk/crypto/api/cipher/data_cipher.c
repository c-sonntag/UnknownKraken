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

#include <uk/crypto/api/cipher/data_cipher.h>
#include <uk/crypto/api/signature/signer.h>
#include <uk/crypto/api/encryption/sym_encrypter.h>
#include <uk/crypto/api/compression/compress.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/crypto/factory/sym_encrypter_factory.h>
#include <uk/crypto/factory/rsa_signer_factory.h>
#include <uk/crypto/factory/sym_key_factory.h>
#include <uk/crypto/impl/envelope/envelope_seal.h>
#include <uk/crypto/impl/envelope/envelope_open.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/defines.h>
#include <uk/utils/ei.h>

bool uk_crypto_cipher_plain_data(unsigned char *plain_data, size_t plain_data_size,
    uk_crypto_public_key *public_key, uk_crypto_private_key *private_key,
    unsigned char **cipher_data, size_t *cipher_data_size, const char *cipher_name,
    const char *digest_name) {

    bool result;
    unsigned char *encrypted_key, *iv, *cipher_data_temp, *signature, *compressed;
    int encrypted_key_len, iv_len, cipher_data_len_temp;
    uk_utils_byte_stream *stream;
    size_t signature_size, compressed_size;
    uk_crypto_signer *signer;

    uk_utils_check_parameter_or_return(plain_data);
    uk_utils_check_parameter_or_return(plain_data_size);
    uk_utils_check_parameter_or_return(public_key);
    uk_utils_check_parameter_or_return(digest_name);
    uk_utils_check_parameter_or_return(cipher_name);

    result = false;
    encrypted_key = NULL;
    iv = NULL;
    cipher_data_temp = NULL;
    stream = uk_utils_byte_stream_create();
    signature = NULL;
    signature_size = 0;
    signer = NULL;
    compressed = NULL;

    if ((compressed = uk_crypto_compress_buf(plain_data, plain_data_size, &compressed_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to compress ReceiverHeader content");
        goto clean_up;
    }

    if (!envelope_seal_buffer(uk_crypto_public_key_get_impl(public_key), compressed,
        (int)compressed_size, &encrypted_key, &encrypted_key_len, &iv, &iv_len,
        &cipher_data_temp, &cipher_data_len_temp, cipher_name)) {

        uk_utils_stacktrace_push_msg("Failed to envelope buffer");
        goto clean_up;
    }

    if (private_key) {
        if ((signer = uk_crypto_rsa_signer_create(public_key, private_key, digest_name)) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to create rsa uk_crypto_signer with key pair");
            goto clean_up;
        }

        if (!uk_crypto_signer_sign_buffer(signer, plain_data, plain_data_size, &signature, &signature_size)) {
            uk_utils_stacktrace_push_msg("Failed to sign message with our private key");
            goto clean_up;
        }
    }

    uk_utils_byte_writer_append_int(stream, encrypted_key_len);
    uk_utils_byte_writer_append_int(stream, iv_len);
    uk_utils_byte_writer_append_int(stream, cipher_data_len_temp);
    uk_utils_byte_writer_append_int(stream, (int)signature_size);
    uk_utils_byte_writer_append_int(stream, (int)plain_data_size);
    uk_utils_byte_writer_append_bytes(stream, encrypted_key, (size_t)encrypted_key_len);
    uk_utils_byte_writer_append_bytes(stream, iv, (size_t)iv_len);
    uk_utils_byte_writer_append_bytes(stream, cipher_data_temp, (size_t)cipher_data_len_temp);
    if (signature) {
        uk_utils_byte_writer_append_bytes(stream, signature, signature_size);
    }

    *cipher_data_size = uk_utils_byte_stream_get_size(stream);
    *cipher_data = uk_utils_bytes_create_from_bytes(uk_utils_byte_stream_get_data(stream), *cipher_data_size);

    result = true;

clean_up:
    uk_utils_safe_free(encrypted_key);
    uk_utils_safe_free(iv);
    uk_utils_safe_free(cipher_data_temp);
    uk_utils_byte_stream_destroy(stream);
    /* @todo fix seg fault if uncomment this following line */
    //uk_utils_safe_free(signature);
    uk_crypto_signer_destroy(signer);
    uk_utils_safe_free(compressed);
    return result;
}

bool uk_crypto_decipher_cipher_data(unsigned char *cipher_data,
    size_t cipher_data_size, uk_crypto_private_key *private_key,
    uk_crypto_public_key *public_key, unsigned char **plain_data,
    size_t *plain_data_size, const char *cipher_name,
    const char *digest_name) {

    bool result, verify_signature;
    uk_utils_byte_stream *stream;
    unsigned char *cipher_data_temp, *encrypted_key, *iv, *signature, *compressed;
    int cipher_data_len_temp, encrypted_key_len, iv_len, signature_size, plain_data_size_read, compressed_size;
    uk_crypto_signer *signer;

    uk_utils_check_parameter_or_return(cipher_data);
    uk_utils_check_parameter_or_return(cipher_data_size);
    uk_utils_check_parameter_or_return(private_key);
    uk_utils_check_parameter_or_return(digest_name);
    uk_utils_check_parameter_or_return(cipher_name);

    result = false;
    stream = uk_utils_byte_stream_create();
    cipher_data_temp = NULL;
    encrypted_key = NULL;
    iv = NULL;
    signature = NULL;
    signature_size = 0;
    verify_signature = false;
    signer = NULL;
    compressed = NULL;

    uk_utils_byte_writer_append_bytes(stream, cipher_data, cipher_data_size);
    uk_utils_byte_stream_set_position(stream, 0);

    uk_utils_byte_read_next_int(stream, &encrypted_key_len);
    uk_utils_byte_read_next_int(stream, &iv_len);
    uk_utils_byte_read_next_int(stream, &cipher_data_len_temp);
    uk_utils_byte_read_next_int(stream, &signature_size);
    uk_utils_byte_read_next_int(stream, &plain_data_size_read);

    if (signature_size == 0 && public_key != NULL) {
        uk_utils_stacktrace_push_msg("A public key is specified to verify the signature of the data, but the signature size is equal to 0");
        goto clean_up;
    } else if (signature_size > 0 && public_key == NULL) {
        uk_utils_stacktrace_push_msg("A signature is specified in the data, but no public key is specified");
        goto clean_up;
    } else if (signature_size > 0 && public_key != NULL) {
        verify_signature = true;
    }

    uk_utils_byte_read_next_bytes(stream, &encrypted_key, (size_t)encrypted_key_len);
    uk_utils_byte_read_next_bytes(stream, &iv, (size_t)iv_len);
    uk_utils_byte_read_next_bytes(stream, &cipher_data_temp, (size_t)cipher_data_len_temp);

    if (verify_signature && !uk_utils_byte_read_next_bytes(stream, &signature, signature_size)) {
        uk_utils_stacktrace_push_msg("Failed to read signature field");
        goto clean_up;
    }

    if (!envelope_open_buffer(uk_crypto_private_key_get_impl(private_key),
        cipher_data_temp, cipher_data_len_temp, encrypted_key,
        encrypted_key_len, iv, &compressed, &compressed_size, cipher_name)) {

        uk_utils_stacktrace_push_msg("Failed to open envelope buffer");
        goto clean_up;
    }

    *plain_data_size = plain_data_size_read;

    if ((*plain_data = uk_crypto_decompress_buf(compressed, (size_t)compressed_size, plain_data_size_read)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to decompress ServerHeader content");
        goto clean_up;
    }

    if (verify_signature) {
        if ((signer = uk_crypto_rsa_signer_create(public_key, private_key, digest_name)) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to create signer to verify signature");
            goto clean_up;
        }
        if (!uk_crypto_signer_verify_buffer(signer, *plain_data, *plain_data_size, signature, signature_size)) {
            uk_utils_safe_free(*plain_data);
            *plain_data_size = 0;
            uk_utils_stacktrace_push_msg("Failed to verify the signature of the sender");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    uk_utils_byte_stream_destroy(stream);
    uk_utils_safe_free(cipher_data_temp);
    uk_utils_safe_free(encrypted_key);
    uk_utils_safe_free(iv);
    uk_utils_safe_free(compressed);
    uk_utils_safe_free(signature);
    uk_crypto_signer_destroy(signer);
    return result;
}

bool uk_crypto_cipher_plain_data_default(unsigned char *plain_data, size_t plain_data_size,
    uk_crypto_public_key *public_key, unsigned char **cipher_data, size_t *cipher_data_size) {

    unsigned char *cipher_data_temp;
    size_t cipher_data_size_temp;

    if (!uk_crypto_cipher_plain_data(plain_data, plain_data_size, public_key, NULL, &cipher_data_temp,
        &cipher_data_size_temp, UnknownKrakenCrypto_DEFAULT_CIPHER_NAME, UnknownKrakenCrypto_DEFAULT_DIGEST_NAME)) {

        uk_utils_stacktrace_push_msg("Failed to cipher plain data with default parameters: %s and %s",
            UnknownKrakenCrypto_DEFAULT_CIPHER_NAME, UnknownKrakenCrypto_DEFAULT_DIGEST_NAME);
        return false;
    }

    *cipher_data = cipher_data_temp;
    *cipher_data_size = cipher_data_size_temp;

    return true;
}

bool uk_crypto_decipher_cipher_data_default(unsigned char *cipher_data,
    size_t cipher_data_size, uk_crypto_private_key *private_key,
    unsigned char **plain_data, size_t *plain_data_size) {

    unsigned char *plain_data_temp;
    size_t plain_data_size_temp;

    if (!uk_crypto_decipher_cipher_data(cipher_data, cipher_data_size, private_key,
        NULL, &plain_data_temp, &plain_data_size_temp, UnknownKrakenCrypto_DEFAULT_CIPHER_NAME,
        UnknownKrakenCrypto_DEFAULT_DIGEST_NAME)) {

        uk_utils_stacktrace_push_msg("Failed to decipher cipher data with default parameters: %s and %s",
            UnknownKrakenCrypto_DEFAULT_CIPHER_NAME, UnknownKrakenCrypto_DEFAULT_DIGEST_NAME);
        return false;
    }

    *plain_data = plain_data_temp;
    *plain_data_size = plain_data_size_temp;

    return true;
}
