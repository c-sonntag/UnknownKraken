#ifndef UNKNOWNECHO_PGP_CLIENT_PK_H
#define UNKNOWNECHO_PGP_CLIENT_PK_H

#include <unknownecho/crypto/api/key/public_key.h>

typedef struct {
	char *nickname;
	ue_public_key *pk;
} ue_pgp_client_pk;

#endif
