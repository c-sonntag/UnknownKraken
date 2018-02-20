#ifndef UNKNOWNECHO_FILE_UTILITY_H
#define UNKNOWNECHO_FILE_UTILITY_H

#include <stddef.h>
#include <stdio.h>

#include <unknownecho/bool.h>

bool ue_is_file_exists(const char *file_name);

size_t ue_get_file_size(FILE *fd);

char *ue_read_file(const char *file_name);

bool ue_write_file(const char *file_name, char *data);

unsigned char *ue_read_binary_file(const char *file_name, size_t *size);

bool ue_write_binary_file(const char *file_name, unsigned char *data, size_t size);

#endif
