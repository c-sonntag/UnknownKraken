#ifndef UNKNOWNECHO_COMPRESS_IMPL_H
#define UNKNOWNECHO_COMPRESS_IMPL_H

#include <unknownecho/bool.h>

#include <stdio.h>
#include <stddef.h>

bool ue_deflate_compress(unsigned char *plaintext, size_t plaintext_len, unsigned char **compressed_text, size_t *compressed_len);

bool ue_inflate_decompress(unsigned char *compressed_text, size_t compressed_len, unsigned char **decompressed_text, size_t decompressed_len);

bool ue_deflate_compress_file(FILE *source, FILE *dest, int level);

bool ue_inflate_decompress_file(FILE *source, FILE *dest);

#endif
