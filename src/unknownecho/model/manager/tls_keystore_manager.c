#include <unknownecho/model/manager/tls_keystore_manager.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/crypto/api/errorHandling/crypto_error_handling.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/fileSystem/file_utility.h>

#include <string.h>


static bool ue_tls_keystore_manager_load(ue_tls_keystore_manager *manager);

static void ue_tls_keystore_manager_unload(ue_tls_keystore_manager *manager);

static bool ue_tls_keystore_manager_unlock(ue_tls_keystore_manager *manager);

static bool ue_tls_keystore_manager_lock(ue_tls_keystore_manager *manager);


static bool ue_tls_keystore_manager_load(ue_tls_keystore_manager *manager) {
	if (manager->loaded) {
		return true;
	}

	ue_safe_alloc(manager->keystore, ue_tls_keystore, 1);
	if (manager->ca_cert_path) {
		manager->keystore->verify_peer = true;
	} else {
		manager->keystore->verify_peer = false;
	}
	manager->keystore->tls = NULL;

    if (!(manager->keystore->ctx = ue_tls_context_create(manager->method))) {
        ue_stacktrace_push_msg("Failed to create TLS context");
        ue_safe_free(manager->keystore);
        return false;
    }

    if (!ue_tls_context_load_certificates(manager->keystore->ctx, manager->passphrase, manager->ca_cert_path, manager->cert_path, manager->key_path)) {
        ue_stacktrace_push_msg("Failed to load certificates");
        ue_tls_context_destroy(manager->keystore->ctx);
        ue_safe_free(manager->keystore);
        return false;
    }

    manager->loaded = true;

    return true;
}

static void ue_tls_keystore_manager_unload(ue_tls_keystore_manager *manager) {
	if (!manager->loaded) {
		return;
	}

	if (manager && manager->keystore) {
		if (manager->keystore->ctx) {
            ue_tls_context_destroy(manager->keystore->ctx);
	        manager->keystore->ctx = NULL;
	    }
	    if (manager->keystore->tls) {
            ue_tls_connection_destroy(manager->keystore->tls);
            manager->keystore->tls = NULL;
        }
		ue_safe_free(manager->keystore);
		manager->keystore = NULL;
		manager->loaded = false;
	}
}

ue_tls_keystore_manager *ue_tls_keystore_manager_init(char *ca_cert_path, char *cert_path, char *key_path, ue_tls_method *method, char *passphrase, char *password) {
	ue_tls_keystore_manager *manager;

	ue_safe_alloc(manager, ue_tls_keystore_manager, 1);
	if (ca_cert_path) {
		/*if (!ue_is_file_exists(ca_cert_path)) {
			ue_stacktrace_push_msg("CA certificate '%s' doesn't exists", ca_cert_path);
			ue_safe_free(manager);
			return NULL;
		}*/
		manager->ca_cert_path = ue_string_create_from(ca_cert_path);
	} else {
		manager->ca_cert_path = NULL;
	}

	manager->cert_path = ue_string_create_from(cert_path);
	manager->key_path = ue_string_create_from(key_path);
	manager->keystore = NULL;
	manager->loaded = false;
	manager->locked = false;
	manager->method = method;
	manager->passphrase = passphrase;
	manager->password = password;

	/*if (!ue_is_file_exists(cert_path)) {
		ue_logger_info("Specified certificate '%s' doesn't exists. Generating...", cert_path);
		if (!ue_x509_certificate_generate_signed(ca_certificate, ca_private_key, "FR", "CLIENT1", &client1_certificate, &client1_private_key)) {
	        ue_logger_error("Failed to generate certificate signed by CA, for client 1");
	        goto failed;
	    }

	    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "res/tls3/ssl_client1.crt", "res/tls3/ssl_client1.key")) {
	        ue_logger_error("Failed to print signed certificate and private key to files, for client 1");
	        goto failed;;
	    }
	}*/

	if (!ue_tls_keystore_manager_unlock(manager)) {
		ue_stacktrace_push_msg("Failed to unlock TLS keystore");
		goto failed;
	}

	if (!ue_tls_keystore_manager_load(manager)) {
		ue_stacktrace_push_msg("Failed to load TLS keystore");
		goto failed;
	}

	return manager;

failed:
	ue_tls_keystore_manager_uninit(manager);
	return NULL;
}

void ue_tls_keystore_manager_uninit(ue_tls_keystore_manager *manager) {
	if (manager) {
		ue_safe_free(manager->ca_cert_path);
		ue_safe_free(manager->cert_path);
		ue_safe_free(manager->key_path);
		if (manager->loaded) {
			if (manager->locked) {
				ue_tls_keystore_manager_unlock(manager);
			}
			ue_tls_keystore_manager_unload(manager);
			ue_tls_keystore_manager_lock(manager);
		}
		ue_safe_free(manager);
	}
}

static bool ue_tls_keystore_manager_unlock(ue_tls_keystore_manager *manager) {
	if (!manager->locked) {
		return true;
	}

	//tls_keystore_manager_load(manager);
	/* decrypt files */

	manager->locked = false;

	return true;
}

static bool ue_tls_keystore_manager_lock(ue_tls_keystore_manager *manager) {
	if (manager->locked) {
		return true;
	}

	/*ue_tls_keystore_manager_unload(manager);*/
	/* encrypt files */

	manager->locked = true;

	return true;
}

ue_tls_keystore *ue_tls_keystore_manager_get_keystore(ue_tls_keystore_manager *manager) {
	if (manager->keystore) {
		return manager->keystore;
	}

	if (manager->locked) {
		ue_tls_keystore_manager_unlock(manager);
	}

	if (!manager->loaded) {
		//tls_keystore_manager_load(manager);
	}

	/*ue_tls_keystore_manager_unload(manager);*/
	ue_tls_keystore_manager_lock(manager);

	return manager->keystore;
}

bool ue_tls_keystore_manager_verify_peer(ue_tls_keystore_manager *manager) {
    return ue_tls_connection_verify_peer_certificate(ue_tls_keystore_manager_get_keystore(manager)->tls);
}
