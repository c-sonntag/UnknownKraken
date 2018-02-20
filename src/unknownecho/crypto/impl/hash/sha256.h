#ifndef UNKNOWNECHO_SHA256_H
#define UNKNOWNECHO_SHA256_H

#include <unknownecho/bool.h>

#include <stddef.h>

bool ue_sha256(const unsigned char *message, size_t message_len, unsigned char **digest, unsigned int *digest_len);

#endif
