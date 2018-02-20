#ifndef UNKNOWNECHO_PGP_KEYSTORE_H
#define UNKNOWNECHO_PGP_KEYSTORE_H

#include <unknownecho/model/entity/pgp_client_pk.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>

typedef struct {
	ue_public_key *pk;
	ue_private_key *sk;
	ue_public_key *server_pk;
	ue_pgp_client_pk **other_clients_pk;
	int other_clients_pk_number;
} ue_pgp_keystore;

#endif
