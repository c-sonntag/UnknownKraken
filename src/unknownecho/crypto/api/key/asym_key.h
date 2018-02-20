#ifndef UNKNOWNECHO_ASYM_KEY_H
#define UNKNOWNECHO_ASYM_KEY_H

#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

#include <stdio.h>

typedef struct {
    ue_public_key *pk;
    ue_private_key *sk;
} ue_asym_key;

ue_asym_key *ue_asym_key_create(ue_public_key *pk, ue_private_key *sk);

void ue_asym_key_destroy(ue_asym_key *akey);

void ue_asym_key_destroy_all(ue_asym_key *akey);

bool ue_asym_key_is_valid(ue_asym_key *akey);

bool ue_asym_key_print(ue_asym_key *akey, FILE *out_fd);

#endif
