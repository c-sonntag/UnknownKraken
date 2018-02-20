#ifndef UNKNOWNECHO_SYM_KEY_H
#define UNKNOWNECHO_SYM_KEY_H

#include <unknownecho/bool.h>

#include <stddef.h>

typedef struct {
	unsigned char *data;
	size_t size;
} ue_sym_key;

ue_sym_key *ue_sym_key_create(unsigned char *data, size_t size);

void ue_sym_key_destroy(ue_sym_key *key);

size_t ue_sym_key_get_min_size();

bool ue_sym_key_is_valid(ue_sym_key *key);

#endif
