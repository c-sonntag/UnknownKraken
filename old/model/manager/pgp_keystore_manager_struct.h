#ifndef UNKNOWNECHO_PGP_KEYSTORE_MANAGER_STRUCT_H
#define UNKNOWNECHO_PGP_KEYSTORE_MANAGER_STRUCT_H

#include <unknownecho/model/entity/pgp_keystore.h>
#include <unknownecho/bool.h>

typedef struct {
	char *ue_public_key_path;
	char *ue_private_key_path;
	char *server_public_key_path;
	char *clients_pk_folder_path;
	ue_pgp_keystore *keystore;
	bool loaded;
	bool locked;
	char *password;
} ue_pgp_keystore_manager;

#endif
