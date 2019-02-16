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

#include <uecm/impl/compression/compress_impl.h>
#include <uecm/impl/errorHandling/zlib_error_handling.h>
#include <ueum/ueum.h>

#include <ei/ei.h>

#undef HAVE_UNISTD_H
#include <zlib.h>

#include <stdlib.h>
#include <limits.h>

#define CHUNK 16384

bool uecm_deflate_compress(unsigned char *plaintext, size_t plaintext_len, unsigned char **compressed_text, size_t *compressed_len) {
    uLong len, tmp_compr_len;
    Byte *compr;
    int error_code;

    if (plaintext_len > ULONG_MAX) {
        ei_stacktrace_push_msg("plaintext_len=%ld > ULONG_MAX=%ld", plaintext_len, ULONG_MAX);
        return false;
    }

    /* Safe to cast plaintext_len to uLong because plaintext_len is <= ULONG_MAX */
    len = compressBound((uLong)plaintext_len);
    compr = NULL;
    tmp_compr_len = len;

    ueum_safe_alloc(compr, Byte, len);

    /* Safe to cast plaintext_len to uLong because plaintext_len is <= ULONG_MAX */
    if ((error_code = compress(compr, &tmp_compr_len, (const Bytef *)plaintext, (uLong)plaintext_len)) != Z_OK) {
        uecm_zlib_error_handling(error_code);
        return false;
    }

    *compressed_text = (unsigned char *)compr;
    *compressed_len = tmp_compr_len;

    return true;
}

bool uecm_inflate_decompress(unsigned char *compressed_text, size_t compressed_len, unsigned char **decompressed_text, size_t decompressed_len) {
    uLong tmp_decompr_len;
    Byte *decompr;
    int error_code;

    if (decompressed_len > ULONG_MAX) {
        ei_stacktrace_push_msg("plaintext_len=%ld > ULONG_MAX=%ld", decompressed_len, ULONG_MAX);
        return false;
    }

    /* Safe to cast plaintext_len to uLong because plaintext_len is <= ULONG_MAX */
    tmp_decompr_len = (uLong)decompressed_len;
    decompr = NULL;
    ueum_safe_alloc(decompr, Byte, tmp_decompr_len);

    /* Safe to cast plaintext_len to uLong because plaintext_len is <= ULONG_MAX */
    if ((error_code = uncompress(decompr, &tmp_decompr_len, (Byte *)compressed_text, (uLong)compressed_len)) != Z_OK) {
        uecm_zlib_error_handling(error_code);
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
bool uecm_deflate_compress_file(FILE *source, FILE *dest, int level) {
    int error_code, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    size_t r;

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    error_code = deflateInit(&strm, level);
    if (error_code != Z_OK) {
        uecm_zlib_error_handling(error_code);
        return false;
    }

    /* compress until end of file */
    do {
        r = fread(in, 1, CHUNK, source);
        if (r > UINT_MAX) {
            ei_stacktrace_push_msg("Stop compress to prevent data loss because fread result > to UINT_MAX");
            (void)deflateEnd(&strm);
            return false;
        }
        /* Safe to cast size_t to uInt as r is < to UINT_MAX */
        strm.avail_in = (uInt)r;
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            uecm_zlib_error_handling(error_code);
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
                uecm_zlib_error_handling(error_code);
                return false;
            }

            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                uecm_zlib_error_handling(error_code);
                return false;
            }

        } while (strm.avail_out == 0);

        /* all input will be used */
        if (strm.avail_in != 0) {
            ei_stacktrace_push_msg("All input is not use");
            (void)deflateEnd(&strm);
            return false;
        }

        /* done when last data in file processed */
    } while (flush != Z_FINISH);

    /* stream will be complete */
    if (error_code != Z_STREAM_END) {
        (void)deflateEnd(&strm);
        uecm_zlib_error_handling(error_code);
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
bool uecm_inflate_decompress_file(FILE *source, FILE *dest) {
    int error_code;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];
    size_t r;

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    error_code = inflateInit(&strm);
    if (error_code != Z_OK) {
        uecm_zlib_error_handling(error_code);
        return false;
    }

    /* decompress until deflate stream ends or end of file */
    do {
        r = fread(in, 1, CHUNK, source);
        if (r > UINT_MAX) {
            ei_stacktrace_push_msg("Stop compress to prevent data loss because fread result > to UINT_MAX");
            (void)deflateEnd(&strm);
            return false;
        }
        /* Safe to cast size_t to uInt as r is < to UINT_MAX */
        strm.avail_in = (uInt)r;
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            uecm_zlib_error_handling(error_code);
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
                uecm_zlib_error_handling(error_code);
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
                    uecm_zlib_error_handling(error_code);
                    return false;
            }

            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                uecm_zlib_error_handling(error_code);
                return false;
            }
        } while (strm.avail_out == 0);

    /* done when inflate() says it's done */
    } while (error_code != Z_STREAM_END);

    /* clean up and error_codeurn */
    (void)inflateEnd(&strm);

    if (error_code != Z_STREAM_END) {
        uecm_zlib_error_handling(error_code);
        return false;
    }

    return true;
}
