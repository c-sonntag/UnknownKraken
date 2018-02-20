#ifndef UNKNOWNECHO_HASHER_H
#define UNKNOWNECHO_HASHER_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct ue_hasher ue_hasher;

ue_hasher *ue_hasher_create();

void ue_hasher_destroy(ue_hasher *h);

bool ue_hasher_init(ue_hasher *h, const char *algorithm);

unsigned char *ue_hasher_digest(ue_hasher *h, const unsigned char *message, size_t message_len, size_t *digest_len);

int ue_hasher_get_digest_size(ue_hasher *h);

#endif
