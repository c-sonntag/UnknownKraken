#include <unknownecho/model/manager/pgp_keystore_manager.h>
#include <unknownecho/model/entity/pgp_client_pk.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/internal_error.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <string.h>

static bool ue_pgp_keystore_manager_load(ue_pgp_keystore_manager *manager);

static void ue_pgp_keystore_manager_unload(ue_pgp_keystore_manager *manager);

static bool ue_pgp_keystore_manager_unlock(ue_pgp_keystore_manager *manager);

static bool ue_pgp_keystore_manager_lock(ue_pgp_keystore_manager *manager);


static bool ue_pgp_keystore_manager_load(ue_pgp_keystore_manager *manager) {
	if (manager->loaded) {
		return true;
	}

	ue_safe_alloc(manager->keystore, ue_pgp_keystore, 1);
	manager->keystore->pk = NULL;
	manager->keystore->sk = NULL;
	manager->keystore->server_pk = NULL;
	manager->keystore->other_clients_pk = NULL;
	manager->keystore->other_clients_pk_number = 0;

	if (!(manager->keystore->pk = ue_rsa_public_key_create_pk_from_file(manager->ue_public_key_path))) {
		ue_stacktrace_push_msg("Failed to load pk from specified file");
		return false;
	}

	if (!(manager->keystore->sk = ue_rsa_private_key_create_sk_from_file(manager->ue_private_key_path))) {
		ue_stacktrace_push_msg("Failed to load sk from specified file");
		return false;
	}

	if (!(manager->keystore->server_pk = ue_rsa_public_key_create_pk_from_file(manager->server_public_key_path))) {
		ue_stacktrace_push_msg("Failed to load server pk from specified file");
	}

	manager->keystore->other_clients_pk_number = 2;
	ue_safe_alloc(manager->keystore->other_clients_pk, ue_pgp_client_pk *, manager->keystore->other_clients_pk_number);

	ue_safe_alloc(manager->keystore->other_clients_pk[0], ue_pgp_client_pk, 1);
	manager->keystore->other_clients_pk[0]->nickname = ue_string_create_from("src");
	if (!(manager->keystore->other_clients_pk[0]->pk = ue_rsa_public_key_create_pk_from_file("res/pem/c1_pgp_pub.pem"))) {
		ue_stacktrace_push_msg("Failed to load c1 pgp pub key");
	}

	ue_safe_alloc(manager->keystore->other_clients_pk[1], ue_pgp_client_pk, 1);
	manager->keystore->other_clients_pk[1]->nickname = ue_string_create_from("dest");
	if (!(manager->keystore->other_clients_pk[1]->pk = ue_rsa_public_key_create_pk_from_file("res/pem/c2_pgp_pub.pem"))) {
		ue_stacktrace_push_msg("Failed to load c2 pgp pub key");
	}

	manager->loaded = true;

	return true;
}

static void ue_pgp_keystore_manager_unload_clean_up(ue_pgp_keystore_manager *manager) {
	int i;

	if (manager && manager->keystore) {
		ue_public_key_destroy(manager->keystore->server_pk);
		if (manager->keystore->other_clients_pk) {
			for (i = 0; i < manager->keystore->other_clients_pk_number; i++) {
				ue_safe_free(manager->keystore->other_clients_pk[i]->nickname);
				ue_public_key_destroy(manager->keystore->other_clients_pk[i]->pk);
				ue_safe_free(manager->keystore->other_clients_pk[i]);
				manager->keystore->other_clients_pk[i] = NULL;
			}
			ue_safe_free(manager->keystore->other_clients_pk);
			manager->keystore->other_clients_pk = NULL;
		}
		manager->keystore->other_clients_pk_number = 0;
		ue_safe_free(manager->keystore);
		manager->keystore = NULL;
	}
}

static void ue_pgp_keystore_manager_unload(ue_pgp_keystore_manager *manager) {
	if (!manager->loaded) {
		return;
	}

	ue_pgp_keystore_manager_unload_clean_up(manager);
	manager->keystore = NULL;

	manager->loaded = false;
}

ue_pgp_keystore_manager *ue_pgp_keystore_manager_init(char *ue_public_key_path, char *ue_private_key_path, char *server_public_key_path, char *password) {
	ue_pgp_keystore_manager *manager;

	if (!ue_is_file_exists(ue_public_key_path)) {
		ue_stacktrace_push_msg("Public key file not found");
		return false;
	}

	if (!ue_is_file_exists(ue_private_key_path)) {
		ue_stacktrace_push_msg("Private key file not found");
		return false;
	}

	if (!ue_is_file_exists(server_public_key_path)) {
		ue_stacktrace_push_msg("Server public key file not found");
		return false;
	}

	ue_safe_alloc(manager, ue_pgp_keystore_manager, 1);
	manager->ue_public_key_path = ue_string_create_from(ue_public_key_path);
	manager->ue_private_key_path = ue_string_create_from(ue_private_key_path);
	manager->server_public_key_path = ue_string_create_from(server_public_key_path);
	manager->clients_pk_folder_path = NULL;
	if (password) {
		manager->password = ue_string_create_from(password);
	} else {
		manager->password = NULL;
	}
	manager->keystore = NULL;
	manager->loaded = false;
	manager->locked = false;

	if (!ue_pgp_keystore_manager_unlock(manager)) {
		ue_stacktrace_push_msg("Failed to unlock pgp keystore");
		goto failed;
	}

	if (!ue_pgp_keystore_manager_load(manager)) {
		ue_stacktrace_push_msg("Failed to load pgp keystore");
		goto failed;
	}

	return manager;

failed:
	ue_pgp_keystore_manager_unload_clean_up(manager);
	ue_pgp_keystore_manager_uninit(manager);
	return NULL;
}

void ue_pgp_keystore_manager_uninit(ue_pgp_keystore_manager *manager) {
	if (manager) {
		ue_safe_free(manager->ue_public_key_path);
		ue_safe_free(manager->ue_private_key_path);
		ue_safe_free(manager->server_public_key_path);
		ue_safe_free(manager->clients_pk_folder_path);
		ue_safe_free(manager->password);
		if (manager->loaded) {
			if (manager->locked) {
				ue_pgp_keystore_manager_unlock(manager);
			}
			ue_pgp_keystore_manager_unload(manager);
			ue_pgp_keystore_manager_lock(manager);
		}
		ue_safe_free(manager);
	}
}

static bool ue_pgp_keystore_manager_unlock(ue_pgp_keystore_manager *manager) {
	if (!manager->locked) {
		return true;
	}

	/*TRY_OR_RETURN_MSG(ue_pgp_keystore_manager_load(manager), "Failed to load pgp keystore")*/
	/* decrypt files */

	manager->locked = false;

	return true;
}

static bool ue_pgp_keystore_manager_lock(ue_pgp_keystore_manager *manager) {
	if (manager->locked) {
		return true;
	}

	/*ue_pgp_keystore_manager_unload(manager);*/
	/* encrypt files */

	manager->locked = true;

	return true;
}

ue_pgp_keystore *ue_pgp_keystore_manager_get_keystore(ue_pgp_keystore_manager *manager) {
	if (manager->keystore) {
		return manager->keystore;
	}

	if (manager->locked) {
		if (!ue_pgp_keystore_manager_unlock(manager)) {
			ue_stacktrace_push_msg("Failed to unlock pgp keystore");
			return NULL;
		}
	}

	/*if (!manager->loaded) {
		TRY_OR_RETURN_MSG(ue_pgp_keystore_manager_load(manager), "Failed to load pgp keystore");
	}*/

	/*ue_pgp_keystore_manager_unload(manager);*/
	if (!ue_pgp_keystore_manager_lock(manager)) {
		ue_stacktrace_push_msg("Failed to lock pgp keystore");
		return NULL;
	}

	return manager->keystore;
}

ue_public_key *ue_pgp_keystore_manager_get_pk_from_nickname(ue_pgp_keystore_manager *manager, char *nickname) {
	int i;

	ue_check_parameter_or_return(manager);
	ue_check_parameter_or_return(manager->keystore);
	ue_check_parameter_or_return(manager->keystore->other_clients_pk);
	ue_check_parameter_or_return(nickname);

	for (i = 0; i < manager->keystore->other_clients_pk_number; i++) {
		if (strcmp(manager->keystore->other_clients_pk[i]->nickname, nickname) == 0) {
			return manager->keystore->other_clients_pk[i]->pk;
		}
	}

	return NULL;
}
