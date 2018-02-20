#ifndef UNKNOWNECHO_COMPRESS_H
#define UNKNOWNECHO_COMPRESS_H

#include <unknownecho/bool.h>

#include <stddef.h>
#include <stdio.h>

unsigned char *ue_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size);

unsigned char *ue_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size);

bool ue_compress_file(FILE *source, FILE *dest);

bool ue_decompress_file(FILE *source, FILE *dest);

#endif
