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

#include <uk/crypto/api/compression/compress.h>
#include <uk/crypto/impl/compression/compress_impl.h>
#include <uk/utils/ei.h>

unsigned char *uk_crypto_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size) {
    unsigned char *compressed_text;
    size_t compressed_size_tmp;

    compressed_text = NULL;
    *compressed_size = 0;

    if (!uk_crypto_deflate_compress(plaintext, plaintext_size, &compressed_text, &compressed_size_tmp)) {
        uk_utils_stacktrace_push_msg("Failed to compress with deflate algorithm");
        return NULL;
    }

    *compressed_size = compressed_size_tmp;

    return compressed_text;
}

unsigned char *uk_crypto_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size) {
    unsigned char *plaintext;

    plaintext = NULL;

    if (!uk_crypto_inflate_decompress(compressed_text, compressed_text_size, &plaintext, plaintext_size)) {
        uk_utils_stacktrace_push_msg("Failed to decompress with deflate algorithm");
    }

    return plaintext;
}

bool uk_crypto_compress_file(FILE *source, FILE *dest) {
    if (!uk_crypto_deflate_compress_file(source, dest, -1)) {
        uk_utils_stacktrace_push_msg("Failed to compress file with deflate algorithm");
        return false;
    }
    return true;
}

bool uk_crypto_decompress_file(FILE *source, FILE *dest) {
    if (!uk_crypto_inflate_decompress_file(source, dest)) {
        uk_utils_stacktrace_push_msg("Failed to decompress file with deflate algorithm");
        return false;
    }
    return true;
}
