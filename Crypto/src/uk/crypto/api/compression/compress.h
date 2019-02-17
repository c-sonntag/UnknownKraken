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

/**
 *  @file      compress.h
 *  @brief     Compress/decompress byte or file.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_COMPRESS_H
#define UnknownKrakenCrypto_COMPRESS_H

#include <uk/utils/ueum.h>

#include <stddef.h>
#include <stdio.h>

unsigned char *uk_crypto_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size);

unsigned char *uk_crypto_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size);

bool uk_crypto_compress_file(FILE *source, FILE *dest);

bool uk_crypto_decompress_file(FILE *source, FILE *dest);

#endif
