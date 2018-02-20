#ifndef UNKNOWNECHO_TLS_KEYSTORE_H
#define UNKNOWNECHO_TLS_KEYSTORE_H

#include <unknownecho/bool.h>
#include <unknownecho/network/api/tls/tls_connection.h>
#include <unknownecho/network/api/tls/tls_context.h>

typedef struct {
	ue_tls_connection *tls;
	ue_tls_context *ctx;
	bool verify_peer;
} ue_tls_keystore;

#endif
