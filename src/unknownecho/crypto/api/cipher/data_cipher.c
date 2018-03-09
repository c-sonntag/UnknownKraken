/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/api/signature/signer.h>
#include <unknownecho/crypto/api/encryption/sym_encrypter.h>
#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/crypto/impl/envelope/envelope_seal.h>
#include <unknownecho/crypto/impl/envelope/envelope_open.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

bool ue_cipher_plain_data(unsigned char *plain_data, size_t plain_data_size,
    ue_public_key *public_key, ue_private_key *private_key,
    unsigned char **cipher_data, size_t *cipher_data_size, const char *cipher_name,
    const char *digest_name) {

    bool result;
    unsigned char *encrypted_key, *iv, *cipher_data_temp, *signature, *compressed;
    int encrypted_key_len, iv_len, cipher_data_len_temp;
    ue_byte_stream *stream;
    size_t signature_size, compressed_size;
    ue_signer *signer;

    result = false;
    encrypted_key = NULL;
    iv = NULL;
    cipher_data_temp = NULL;
    stream = ue_byte_stream_create();
    signature = NULL;
    signature_size = 0;
    signer = NULL;
    compressed = NULL;

    if (!(compressed = ue_compress_buf(plain_data, plain_data_size, &compressed_size))) {
		ue_stacktrace_push_msg("Failed to compress ReceiverHeader content");
		goto clean_up;
	}

    if (!envelope_seal_buffer(ue_public_key_get_impl(public_key), compressed,
        (int)compressed_size, &encrypted_key, &encrypted_key_len, &iv, &iv_len,
    	&cipher_data_temp, &cipher_data_len_temp, cipher_name)) {

        ue_stacktrace_push_msg("Failed to envelope buffer");
        goto clean_up;
    }

    if (private_key) {
        if (!(signer = ue_rsa_signer_create(public_key, private_key, digest_name))) {
            ue_stacktrace_push_msg("Failed to create rsa ue_signer with key pair");
            goto clean_up;
        }

        if (!ue_signer_sign_buffer(signer, plain_data, plain_data_size, &signature, &signature_size)) {
            ue_stacktrace_push_msg("Failed to sign message with our private key");
            goto clean_up;
        }
    }

    ue_byte_writer_append_int(stream, encrypted_key_len);
    ue_byte_writer_append_int(stream, iv_len);
    ue_byte_writer_append_int(stream, cipher_data_len_temp);
    ue_byte_writer_append_int(stream, (int)signature_size);
    ue_byte_writer_append_int(stream, (int)plain_data_size);
    ue_byte_writer_append_bytes(stream, encrypted_key, (size_t)encrypted_key_len);
    ue_byte_writer_append_bytes(stream, iv, (size_t)iv_len);
    ue_byte_writer_append_bytes(stream, cipher_data_temp, (size_t)cipher_data_len_temp);
    if (signature) {
        ue_byte_writer_append_bytes(stream, signature, signature_size);
    }

    *cipher_data_size = ue_byte_stream_get_size(stream);
    *cipher_data = ue_bytes_create_from_bytes(ue_byte_stream_get_data(stream), *cipher_data_size);

    result = true;

clean_up:
    ue_safe_free(encrypted_key);
    ue_safe_free(iv);
    ue_safe_free(cipher_data_temp);
    ue_byte_stream_destroy(stream);
    ue_safe_free(signature);
    ue_signer_destroy(signer);
    ue_safe_free(compressed);
    return result;
}

bool ue_decipher_cipher_data(unsigned char *cipher_data,
    size_t cipher_data_size, ue_private_key *private_key,
    ue_public_key *public_key, unsigned char **plain_data,
    size_t *plain_data_size, const char *cipher_name,
    const char *digest_name) {

    bool result, verify_signature;
    ue_byte_stream *stream;
    unsigned char *cipher_data_temp, *encrypted_key, *iv, *signature, *compressed;
    int cipher_data_len_temp, encrypted_key_len, iv_len, signature_size, plain_data_size_read, compressed_size;
    ue_signer *signer;

    result = false;
    stream = ue_byte_stream_create();
    cipher_data_temp = NULL;
    encrypted_key = NULL;
    iv = NULL;
    signature = NULL;
    signature_size = 0;
    verify_signature = false;
    signer = NULL;
    compressed = NULL;

    ue_byte_writer_append_bytes(stream, cipher_data, cipher_data_size);
    ue_byte_stream_set_position(stream, 0);

    ue_byte_read_next_int(stream, &encrypted_key_len);
    ue_byte_read_next_int(stream, &iv_len);
    ue_byte_read_next_int(stream, &cipher_data_len_temp);
    ue_byte_read_next_int(stream, &signature_size);
    ue_byte_read_next_int(stream, &plain_data_size_read);

    if (signature_size == 0 && public_key != NULL) {
        ue_stacktrace_push_msg("A public key is specified to verify the signature of the data, but the signature size is equal to 0");
        goto clean_up;
    } else if (signature_size > 0 && public_key == NULL) {
        ue_stacktrace_push_msg("A signature is specified in the data, but no public key is specified");
        goto clean_up;
    } else if (signature_size > 0 && public_key != NULL) {
        verify_signature = true;
    }

    ue_byte_read_next_bytes(stream, &encrypted_key, (size_t)encrypted_key_len);
    ue_byte_read_next_bytes(stream, &iv, (size_t)iv_len);
    ue_byte_read_next_bytes(stream, &cipher_data_temp, (size_t)cipher_data_len_temp);

    if (verify_signature && !ue_byte_read_next_bytes(stream, &signature, signature_size)) {
		ue_stacktrace_push_msg("Failed to read signature field");
		goto clean_up;
	}

    if (!envelope_open_buffer(ue_private_key_get_impl(private_key),
        cipher_data_temp, cipher_data_len_temp, encrypted_key,
        encrypted_key_len, iv, &compressed, &compressed_size, cipher_name)) {

        ue_stacktrace_push_msg("Failed to open envelope buffer");
        goto clean_up;
    }

    *plain_data_size = plain_data_size_read;

    if (!(*plain_data = ue_decompress_buf(compressed, (size_t)compressed_size, plain_data_size_read))) {
		ue_stacktrace_push_msg("Failed to decompress ServerHeader content");
		goto clean_up;
	}

    if (verify_signature) {
        if (!(signer = ue_rsa_signer_create(public_key, private_key, digest_name))) {
            ue_stacktrace_push_msg("Failed to create signer to verify signature");
            goto clean_up;
        }
    	if (!ue_signer_verify_buffer(signer, *plain_data, *plain_data_size, signature, signature_size)) {
            ue_safe_free(*plain_data);
            *plain_data_size = 0;
    		ue_stacktrace_push_msg("Failed to verify the signature of the sender");
    		goto clean_up;
    	}
    }

    result = true;

clean_up:
    ue_byte_stream_destroy(stream);
    ue_safe_free(cipher_data_temp);
    ue_safe_free(encrypted_key);
    ue_safe_free(iv);
    ue_safe_free(compressed);
    ue_safe_free(signature);
    ue_signer_destroy(signer);
    return result;
}
