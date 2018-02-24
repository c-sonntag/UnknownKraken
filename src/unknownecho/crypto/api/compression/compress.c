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

#include <unknownecho/crypto/api/compression/compress.h>
#include <unknownecho/crypto/impl/compression/compress_impl.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

unsigned char *ue_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size) {
	unsigned char *compressed_text;
	size_t compressed_size_tmp;

	compressed_text = NULL;
	*compressed_size = 0;

	if (!ue_deflate_compress(plaintext, plaintext_size, &compressed_text, &compressed_size_tmp)) {
		ue_stacktrace_push_msg("Failed to compress with deflate algorithm");
		return NULL;
	}

	*compressed_size = compressed_size_tmp;

	return compressed_text;
}

unsigned char *ue_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size) {
	unsigned char *plaintext;

	plaintext = NULL;

	if (!ue_inflate_decompress(compressed_text, compressed_text_size, &plaintext, plaintext_size)) {
		ue_stacktrace_push_msg("Failed to decompress with deflate algorithm");
	}

	return plaintext;
}

bool ue_compress_file(FILE *source, FILE *dest) {
	if (!ue_deflate_compress_file(source, dest, -1)) {
		ue_stacktrace_push_msg("Failed to compress file with deflate algorithm");
		return false;
	}
	return true;
}

bool ue_decompress_file(FILE *source, FILE *dest) {
	if (!ue_inflate_decompress_file(source, dest)) {
		ue_stacktrace_push_msg("Failed to decompress file with deflate algorithm");
		return false;
	}
	return true;
}
