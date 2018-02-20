#ifndef UNKNOWNECHO_PGP_KEYSTORE_MANAGER_H
#define UNKNOWNECHO_PGP_KEYSTORE_MANAGER_H

#include <unknownecho/model/entity/pgp_keystore.h>
#include <unknownecho/model/entity/pgp_client_pk.h>
#include <unknownecho/model/manager/pgp_keystore_manager_struct.h>
#include <unknownecho/bool.h>
#include <unknownecho/crypto/api/key/public_key.h>

ue_pgp_keystore_manager *ue_pgp_keystore_manager_init(char *ue_public_key_path, char *ue_private_key_path, char *server_public_key_path, char *password);

void ue_pgp_keystore_manager_uninit(ue_pgp_keystore_manager *manager);

ue_pgp_keystore *ue_pgp_keystore_manager_get_keystore(ue_pgp_keystore_manager *manager);

ue_public_key *ue_pgp_keystore_manager_get_pk_from_nickname(ue_pgp_keystore_manager *manager, char *nickname);

#endif
