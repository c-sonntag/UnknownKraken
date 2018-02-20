#ifndef UNKNOWNECHO_SYM_KEY_FACTORY_H
#define UNKNOWNECHO_SYM_KEY_FACTORY_H

#include <unknownecho/crypto/api/key/sym_key.h>

ue_sym_key *ue_sym_key_create_random();

ue_sym_key *ue_sym_key_create_from_file(char *file_path);

#endif
