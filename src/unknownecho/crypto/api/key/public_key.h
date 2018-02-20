#ifndef UNKNOWNECHO_PUBLIC_KEY_H
#define UNKNOWNECHO_PUBLIC_KEY_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef enum {
	RSA_PUBLIC_KEY
} ue_public_key_type;

typedef struct ue_public_key ue_public_key;

ue_public_key *ue_public_key_create(ue_public_key_type key_type, void *impl, int bits);

void ue_public_key_destroy(ue_public_key *pk);

int ue_public_key_size(ue_public_key *pk);

bool ue_public_key_is_valid(ue_public_key *pk);

void *ue_public_key_get_impl(ue_public_key *pk);

void *ue_public_key_get_rsa_impl(ue_public_key *pk);

bool ue_public_key_print(ue_public_key *pk, FILE *out_fd);

#endif
