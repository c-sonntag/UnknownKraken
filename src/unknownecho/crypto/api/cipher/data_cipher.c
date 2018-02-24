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
#include <unknownecho/crypto/api/encryption/asym_encrypter.h>
#include <unknownecho/crypto/utils/crypto_random.h>
#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/crypto/factory/sym_encrypter_factory.h>
#include <unknownecho/crypto/factory/asym_encrypter_factory.h>
#include <unknownecho/crypto/factory/rsa_signer_factory.h>
#include <unknownecho/crypto/factory/sym_key_factory.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/byte/byte_reader.h>
#include <unknownecho/byte/byte_utility.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

bool cipher_plain_data(unsigned char *plain_data, size_t plain_data_size, ue_public_key *public_key, ue_private_key *private_key, unsigned char **cipher_data, size_t *cipher_data_size, ue_sym_key *key) {
    bool result;
    ue_byte_stream *header_stream, *cipher_stream, *result_stream;
    unsigned char *iv, *plain_data_size_uchar, *signature, *cipher_data_temp, *compressed, *cipher_header;
    size_t iv_size, plain_data_size_uchar_size, signature_size, cipher_data_size_temp, compressed_size, cipher_header_size;
    ue_signer *signer;
    ue_asym_encrypter *asym_encrypter;
    ue_sym_key *key_used;
    ue_sym_encrypter *sym_encrypter;

    result = false;
    header_stream = ue_byte_stream_create();
    cipher_stream = ue_byte_stream_create();
    result_stream = ue_byte_stream_create();
    iv = NULL;
    plain_data_size_uchar = NULL;
    signature = NULL;
    signature_size = 0;
    cipher_data_temp = NULL;
    compressed = NULL;
    cipher_header = NULL;
    signer = NULL;
    asym_encrypter = NULL;
    key_used = NULL;
    sym_encrypter = NULL;

    if (!key) {
        if (!(key_used = ue_sym_key_create_random())) {
    		ue_stacktrace_push_msg("Failed to get crypto random bytes for server aes key generation");
    		goto clean_up;
    	}
    } else {
        key_used = key;
    }

	/* Generate iv of 16 bytes (because AES-CBC block cipher is 128 bits) */
	ue_safe_alloc(iv, unsigned char, 16);
	if (!(ue_crypto_random_bytes(iv, 16))) {
		ue_stacktrace_push_msg("Failed to get crypto random bytes for IV");
		goto clean_up;
	}
	iv_size = 16;

	/* DeflateDecompress algorithm needs the plaintext size to proceed */
	ue_safe_alloc(plain_data_size_uchar, unsigned char, 4);
	ue_int_to_bytes((int)plain_data_size, plain_data_size_uchar);
	plain_data_size_uchar_size = 4;

    /* Signature with message content digest */
    if (private_key) {
        if (!(signer = ue_rsa_signer_create(public_key, private_key))) {
            ue_stacktrace_push_msg("Failed to create rsa ue_signer with key pair");
            goto clean_up;
        }

        if (!(signature = ue_signer_sign_buffer(signer, plain_data, plain_data_size, &signature_size))) {
            ue_stacktrace_push_msg("Failed to sign message with our private key");
            goto clean_up;
        }
    }

    if (!(ue_byte_writer_append_int(header_stream, (int)key_used->size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_key_len> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(header_stream, (int)iv_size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_iv_len> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_int(header_stream, (int)plain_data_size_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <plain_data_size_uchar_size> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(header_stream, key_used->data, key_used->size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_key> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(header_stream, iv, iv_size))) {
		ue_stacktrace_push_msg("Failed to append <server_aes_iv> field to key header stream");
		goto clean_up;
	}

	if (!(ue_byte_writer_append_bytes(header_stream, plain_data_size_uchar, plain_data_size_uchar_size))) {
		ue_stacktrace_push_msg("Failed to append <decompressed_len_uchar> field to key header stream");
		goto clean_up;
	}

    if (!(asym_encrypter = ue_asym_encrypter_default_create(public_key, NULL))) {
        ue_stacktrace_push_msg("Failed to create asym encrypter from specified public key");
        goto clean_up;
    }

	if (!(cipher_header = ue_asym_encrypter_public_encrypt(asym_encrypter, ue_byte_stream_get_data(header_stream),
		ue_byte_stream_get_size(header_stream), &cipher_header_size))) {
		ue_stacktrace_push_msg("Failed to encrypt server aes iv with server public key");
		goto clean_up;
	}

    if (!(compressed = ue_compress_buf(plain_data, plain_data_size, &compressed_size))) {
		ue_stacktrace_push_msg("Failed to compress ReceiverHeader content");
		goto clean_up;
	}

	sym_encrypter = ue_sym_encrypter_default_create(key_used);
	if (!(cipher_data_temp = ue_sym_encrypter_encrypt(sym_encrypter, compressed, compressed_size, iv, iv_size, &cipher_data_size_temp))) {
		ue_stacktrace_push_msg("Failed to encrypt ReceiverHeader content");
		goto clean_up;
	}

    ue_byte_writer_append_int(cipher_stream, (int)cipher_data_size_temp);
    ue_byte_writer_append_int(cipher_stream, (int)signature_size);
    ue_byte_writer_append_bytes(cipher_stream, cipher_data_temp, cipher_data_size_temp);
    if (signature) {
        ue_byte_writer_append_bytes(cipher_stream, signature, signature_size);
    }

    ue_byte_writer_append_int(result_stream, (int)cipher_header_size);
    ue_byte_writer_append_int(result_stream, (int)ue_byte_stream_get_size(cipher_stream));
    ue_byte_writer_append_bytes(result_stream, cipher_header, cipher_header_size);
    ue_byte_writer_append_bytes(result_stream, ue_byte_stream_get_data(cipher_stream), ue_byte_stream_get_size(cipher_stream));

    if (!(*cipher_data = ue_bytes_create_from_bytes(ue_byte_stream_get_data(result_stream), ue_byte_stream_get_size(result_stream)))) {
		ue_stacktrace_push_msg("Failed to copy server header byte stream to server header field");
		goto clean_up;
	}

	*cipher_data_size = ue_byte_stream_get_size(result_stream);

    result = true;

clean_up:
    ue_byte_stream_destroy(header_stream);
    ue_byte_stream_destroy(cipher_stream);
    ue_byte_stream_destroy(result_stream);
    ue_safe_free(iv);
    ue_safe_free(plain_data_size_uchar);
    ue_safe_free(signature);
    ue_safe_free(cipher_data_temp);
    ue_safe_free(compressed);
    ue_safe_free(cipher_header);
    ue_signer_destroy(signer);
    if (!key) {
        ue_sym_key_destroy(key_used);
    }
    ue_asym_encrypter_destroy(asym_encrypter);
    ue_sym_encrypter_destroy(sym_encrypter);
    return result;
}

bool decipher_cipher_data(unsigned char *cipher_data, size_t cipher_data_size, ue_private_key *private_key, ue_public_key *public_key, unsigned char **plain_data, size_t *plain_data_size) {
    bool result, verify_signature;
    ue_byte_stream *cipher_stream, *header_stream, *cipher_data_stream;
    unsigned char *header, *cipher_data_temp, *cipher_temp, *key_temp, *iv, *signature, *decipher_header, *compressed, *plain_data_size_uchar;
    int read_int;
    size_t header_size, cipher_size_temp, cipher_data_size_temp, key_size_temp, iv_size, signature_size, decipher_header_size, compressed_size, plain_data_size_uchar_size;
    ue_sym_key *key;
    ue_sym_encrypter *sym_encrypter;
    ue_asym_encrypter *asym_encrypter;
    ue_signer *signer;

    result = false;
    verify_signature = false;
    cipher_stream = ue_byte_stream_create();
    header_stream = ue_byte_stream_create();
    cipher_data_stream = ue_byte_stream_create();
    header = NULL;
    cipher_data_temp = NULL;
    cipher_temp = NULL;
    key_temp = NULL;
    iv = NULL;
    signature = NULL;
    decipher_header = NULL;
    compressed = NULL;
    plain_data_size_uchar = NULL;
    key = NULL;
    sym_encrypter = NULL;
    asym_encrypter = NULL;
    signer = NULL;

    if (!ue_byte_writer_append_bytes(cipher_stream, cipher_data, cipher_data_size)) {
		ue_stacktrace_push_msg("Failed to write ciphered raw message to server header stream");
		goto clean_up;
	}
	ue_byte_stream_set_position(cipher_stream, 0);

	if (!ue_byte_read_next_int(cipher_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	header_size = read_int;

    if (!ue_byte_read_next_int(cipher_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	cipher_size_temp = read_int;

    if (!ue_byte_read_next_bytes(cipher_stream, &header, header_size)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

    if (!ue_byte_read_next_bytes(cipher_stream, &cipher_temp, cipher_size_temp)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

    asym_encrypter = ue_asym_encrypter_default_create(NULL, private_key);

	if (!(decipher_header = ue_asym_encrypter_private_decrypt(asym_encrypter, header, header_size, &decipher_header_size))) {
		ue_stacktrace_push_msg("Failed to decrypt key header with our private key");
		goto clean_up;
	}

    if (!ue_byte_writer_append_bytes(header_stream, decipher_header, decipher_header_size)) {
		ue_stacktrace_push_msg("Failed to write ciphered raw message to server header stream");
		goto clean_up;
	}
	ue_byte_stream_set_position(header_stream, 0);

    if (!ue_byte_read_next_int(header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	key_size_temp = read_int;

    if (!ue_byte_read_next_int(header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	iv_size = read_int;

    if (!ue_byte_read_next_int(header_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	plain_data_size_uchar_size = read_int;

    if (!ue_byte_read_next_bytes(header_stream, &key_temp, key_size_temp)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}
    key = ue_sym_key_create(key_temp, key_size_temp);

    if (!ue_byte_read_next_bytes(header_stream, &iv, iv_size)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

	if (!ue_byte_read_next_bytes(header_stream, &plain_data_size_uchar, plain_data_size_uchar_size)) {
		ue_stacktrace_push_msg("Failed to parse <decompressed_len_uchar> field");
		goto clean_up;
	}
	*plain_data_size = ue_bytes_to_int(plain_data_size_uchar);

    if (!ue_byte_writer_append_bytes(cipher_data_stream, cipher_temp, cipher_size_temp)) {
		ue_stacktrace_push_msg("Failed to write ciphered raw message to server header stream");
		goto clean_up;
	}
	ue_byte_stream_set_position(cipher_data_stream, 0);

    if (!ue_byte_read_next_int(cipher_data_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	cipher_data_size_temp = read_int;

    if (!ue_byte_read_next_int(cipher_data_stream, &read_int)) {
		ue_stacktrace_push_msg("Failed to parse <ciphered_key_header_len> field");
		goto clean_up;
	}
	signature_size = read_int;

    if (signature_size == 0 && public_key != NULL) {
        ue_stacktrace_push_msg("A public key is specified to verify the signature of the data, but the signature size is equal to 0");
        goto clean_up;
    } else if (signature_size > 0 && public_key == NULL) {
        ue_stacktrace_push_msg("A signature is specified in the data, but no public key is specified");
        goto clean_up;
    } else if (signature_size > 0 && public_key != NULL) {
        verify_signature = true;
    }

    if (!ue_byte_read_next_bytes(cipher_data_stream, &cipher_data_temp, cipher_data_size_temp)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

    if (verify_signature && !ue_byte_read_next_bytes(cipher_data_stream, &signature, signature_size)) {
		ue_stacktrace_push_msg("Failed to parse <key_header> field");
		goto clean_up;
	}

    sym_encrypter = ue_sym_encrypter_default_create(key);
	if (!(compressed = ue_sym_encrypter_decrypt(sym_encrypter, cipher_data_temp, cipher_data_size_temp, iv, iv_size, &compressed_size))) {
		ue_stacktrace_push_msg("Failed to decrypt ServerHeader content");
		goto clean_up;
	}

    if (!(*plain_data = ue_decompress_buf(compressed, compressed_size, *plain_data_size))) {
		ue_stacktrace_push_msg("Failed to decompress ServerHeader content");
		goto clean_up;
	}

    if (verify_signature) {
        if (!(signer = ue_rsa_signer_create(public_key, private_key))) {
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
    ue_byte_stream_destroy(cipher_stream);
    ue_byte_stream_destroy(header_stream);
    ue_byte_stream_destroy(cipher_data_stream);
    ue_safe_free(header);
    ue_safe_free(cipher_data_temp);
    ue_safe_free(cipher_temp);
    ue_safe_free(key_temp);
    ue_safe_free(iv);
    ue_safe_free(signature);
    ue_safe_free(decipher_header);
    ue_safe_free(compressed);
    ue_safe_free(plain_data_size_uchar);
    ue_sym_key_destroy(key);
    ue_sym_encrypter_destroy(sym_encrypter);
    ue_asym_encrypter_destroy(asym_encrypter);
    ue_signer_destroy(signer);
    return result;
}
