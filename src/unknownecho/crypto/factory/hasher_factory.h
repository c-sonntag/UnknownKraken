#ifndef UNKNOWNECHO_HASHER_FACTORY_H
#define UNKNOWNECHO_HASHER_FACTORY_H

#include <unknownecho/crypto/api/hash/hasher.h>

ue_hasher *ue_hasher_sha256_create();

ue_hasher *ue_hasher_default_create();

#endif
