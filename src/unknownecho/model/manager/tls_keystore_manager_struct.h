#ifndef UNKNOWNECHO_TLS_KEYSTORE_MANAGER_STRUCT_H
#define UNKNOWNECHO_TLS_KEYSTORE_MANAGER_STRUCT_H

#include <unknownecho/model/entity/tls_keystore.h>
#include <unknownecho/bool.h>
#include <unknownecho/network/api/tls/tls_method.h>

typedef struct {
	char *ca_cert_path;
	char *cert_path;
	char *key_path;
	ue_tls_keystore *keystore;
	bool loaded;
	bool locked;
	ue_tls_method *method;
	char *passphrase;
	char *password;
} ue_tls_keystore_manager;

#endif
