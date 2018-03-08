#ifndef UNKNOWNECHO_FRIENDLY_NAME_H
#define UNKNOWNECHO_FRIENDLY_NAME_H

#include <stddef.h>

unsigned char *ue_friendly_name_build(unsigned char *nickname, size_t nickname_size, char *keystore_type, size_t *friendly_name_size);

#endif
