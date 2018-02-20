#ifndef UNKNOWNECHO_CRYPTO_RANDOM_H
#define UNKNOWNECHO_CRYPTO_RANDOM_H

#include <unknownecho/bool.h>

#include <stddef.h>

bool ue_crypto_random_bytes(unsigned char *buffer, size_t buffer_length);

#endif
