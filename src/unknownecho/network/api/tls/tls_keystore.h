#ifndef UNKNOWNECHO_TLS_KEYSTORE_H
#define UNKNOWNECHO_TLS_KEYSTORE_H

#include <unknownecho/bool.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/tls/tls_context.h>
#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/crypto/api/keystore/pkcs12_keystore.h>

typedef struct {
	ue_tls_connection *tls;
	ue_tls_context *ctx;
	bool verify_peer;
	ue_tls_method *method;
	ue_pkcs12_keystore *keystore;
} ue_tls_keystore;

ue_tls_keystore *ue_tls_keystore_create(char *keystore_path, char *passphrase, char *pem_passphrase, ue_tls_method *method);

void ue_tls_keystore_destroy(ue_tls_keystore *tls_keystore);

bool ue_tls_keystore_verify_peer(ue_tls_keystore *tls_keystore);

#endif
