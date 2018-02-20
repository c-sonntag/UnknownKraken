#ifndef UNKNOWNECHO_PRIVATE_KEY_H
#define UNKNOWNECHO_PRIVATE_KEY_H

#include <unknownecho/bool.h>

#include <stdio.h>

typedef enum {
	RSA_PRIVATE_KEY
} ue_private_key_type;

typedef struct ue_private_key ue_private_key;

ue_private_key *ue_private_key_create_from_impl(void *impl);

ue_private_key *ue_private_key_create(ue_private_key_type key_type, void *impl, int bits);

void ue_private_key_destroy(ue_private_key *sk);

int ue_private_key_size(ue_private_key *sk);

bool ue_private_key_is_valid(ue_private_key *sk);

void *ue_private_key_get_impl(ue_private_key *sk);

void *ue_private_key_get_rsa_impl(ue_private_key *sk);

bool ue_private_key_print(ue_private_key *sk, FILE *out_fd);

#endif
