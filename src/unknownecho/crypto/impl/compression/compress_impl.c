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

#include <unknownecho/crypto/impl/compression/compress_impl.h>
#include <unknownecho/crypto/impl/errorHandling/zlib_error_handling.h>
#include <unknownecho/system/alloc.h>

#include <stdlib.h>
#include <zlib.h>

#define CHUNK 16384

bool ue_deflate_compress(unsigned char *plaintext, size_t plaintext_len, unsigned char **compressed_text, size_t *compressed_len) {
    uLong len, tmp_compr_len;
    Byte *compr;
    int error_code;

    len = compressBound(plaintext_len);
    tmp_compr_len = len;

    ue_safe_alloc(compr, Byte, len);

    if ((error_code = compress(compr, &tmp_compr_len, (const Bytef*)plaintext, plaintext_len)) != Z_OK) {
        ue_zlib_error_handling(error_code);
        return false;
    }

    *compressed_text = (unsigned char *)compr;
    *compressed_len = tmp_compr_len;

    return true;
}

bool ue_inflate_decompress(unsigned char *compressed_text, size_t compressed_len, unsigned char **decompressed_text, size_t decompressed_len) {
    uLong tmp_decompr_len;
    Byte *decompr;
    int error_code;

    tmp_decompr_len = (uLong)decompressed_len;
    ue_safe_alloc(decompr, Byte, tmp_decompr_len);

    if ((error_code = uncompress(decompr, &tmp_decompr_len, (Byte *)compressed_text, compressed_len)) != Z_OK) {
        ue_zlib_error_handling(error_code);
        return false;
    }


    *decompressed_text = (unsigned char *)decompr;

    return true;
}

/**
 * Compress from file source to file dest until EOF on source.
 * def() error_codeurns Z_OK on success, Z_MEM_ERROR if memory could not be
 * allocated for processing, Z_STREAM_ERROR if an invalid compression
 * level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
 * version of the library linked do not match, or Z_ERRNO if there is
 * an error reading or writing the files.
 */
bool ue_deflate_compress_file(FILE *source, FILE *dest, int level) {
    int error_code, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    error_code = deflateInit(&strm, level);
    if (error_code != Z_OK) {
        ue_zlib_error_handling(error_code);
        return false;
    }

    /* compress until end of file */
    do {

        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            ue_zlib_error_handling(error_code);
            return false;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /**
         * run deflate() on input until output buffer not full, finish
         * compression if all of source has been read in
         */
        do {

            strm.avail_out = CHUNK;
            strm.next_out = out;

            /* no bad error_codeurn value */
            error_code = deflate(&strm, flush);

            /* state not clobbered */
            if (error_code == Z_STREAM_ERROR) {
                (void)deflateEnd(&strm);
                ue_zlib_error_handling(error_code);
                return false;
            }

            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                ue_zlib_error_handling(error_code);
                return false;
            }

        } while (strm.avail_out == 0);

        /* all input will be used */
        if (strm.avail_in != 0) {
            ue_stacktrace_push_msg("All input is not use");
            (void)deflateEnd(&strm);
            return false;
        }

        /* done when last data in file processed */
    } while (flush != Z_FINISH);

    /* stream will be complete */
    if (error_code != Z_STREAM_END) {
        (void)deflateEnd(&strm);
        ue_zlib_error_handling(error_code);
        return false;
    }


    /* clean up and error_codeurn */
    (void)deflateEnd(&strm);
    return true;
}

/* Decompress from file source to file dest until stream ends or EOF.
   inf() error_codeurns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. */
bool ue_inflate_decompress_file(FILE *source, FILE *dest) {
    int error_code;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    error_code = inflateInit(&strm);
    if (error_code != Z_OK) {
        ue_zlib_error_handling(error_code);
        return false;
    }

    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            ue_zlib_error_handling(error_code);
            return false;
        }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;

            error_code = inflate(&strm, Z_NO_FLUSH);
            /* state not clobbered */
            if (error_code == Z_STREAM_ERROR) {
                (void)deflateEnd(&strm);
                ue_zlib_error_handling(error_code);
                return false;
            }
            switch (error_code) {
                case Z_NEED_DICT:
                    /* and fall through */
                    error_code = Z_DATA_ERROR;
    			break;
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    ue_zlib_error_handling(error_code);
                    return false;
            }

            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                ue_zlib_error_handling(error_code);
                return false;
            }
        } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
    } while (error_code != Z_STREAM_END);

    /* clean up and error_codeurn */
    (void)inflateEnd(&strm);

    if (error_code != Z_STREAM_END) {
        ue_zlib_error_handling(error_code);
        return false;
    }

    return true;
}
