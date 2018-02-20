#ifndef UNKNOWNECHO_BYTE_UTILITY_H
#define UNKNOWNECHO_BYTE_UTILITY_H

#include <stddef.h>

unsigned char *ue_bytes_create_from_string(const char *str);

unsigned char *ue_bytes_create_from_bytes(unsigned char *bytes, size_t size);

void ue_int_to_bytes(int n, unsigned char *bytes);

int ue_bytes_to_int(unsigned char *bytes);

#endif
