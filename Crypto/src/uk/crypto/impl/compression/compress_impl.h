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

#ifndef UnknownKrakenCrypto_COMPRESS_IMPL_H
#define UnknownKrakenCrypto_COMPRESS_IMPL_H

#include <uk/utils/ueum.h>

#include <stdio.h>
#include <stddef.h>

bool uk_crypto_deflate_compress(unsigned char *plaintext, size_t plaintext_len, unsigned char **compressed_text, size_t *compressed_len);

bool uk_crypto_inflate_decompress(unsigned char *compressed_text, size_t compressed_len, unsigned char **decompressed_text, size_t decompressed_len);

bool uk_crypto_deflate_compress_file(FILE *source, FILE *dest, int level);

bool uk_crypto_inflate_decompress_file(FILE *source, FILE *dest);

#endif
