#include <unknownecho/network/api/tls/tls_keystore.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_tls_keystore *ue_tls_keystore_create(char *keystore_path, char *passphrase, char *pem_passphrase, ue_tls_method *method) {
    ue_tls_keystore *tls_keystore;

    ue_safe_alloc(tls_keystore, ue_tls_keystore, 1);

    if (!(tls_keystore->keystore = ue_pkcs12_keystore_load(keystore_path, passphrase, pem_passphrase))) {
        ue_stacktrace_push_msg("Failed to loas pkcs12 keystore from file '%s'", keystore_path);
        ue_safe_free(tls_keystore);
        return NULL;
    }

    tls_keystore->method = method;

    if (!(tls_keystore->ctx = ue_tls_context_create(tls_keystore->method))) {
        ue_stacktrace_push_msg("Failed to create TLS context");
        ue_tls_keystore_destroy(tls_keystore);
        return NULL;
    }

	if (!(ue_tls_context_load_certificates(tls_keystore->ctx, tls_keystore->keystore))) {
        ue_stacktrace_push_msg("Failed to load keystore certificates into TLS context");
        ue_tls_keystore_destroy(tls_keystore);
        return NULL;
    }

	tls_keystore->verify_peer = false;
    tls_keystore->tls = NULL;

    return tls_keystore;
}

void ue_tls_keystore_destroy(ue_tls_keystore *tls_keystore) {
    if (tls_keystore) {
        ue_tls_context_destroy(tls_keystore->ctx);
        ue_tls_connection_destroy(tls_keystore->tls);
        ue_tls_method_destroy(tls_keystore->method);
        ue_pkcs12_keystore_destroy(tls_keystore->keystore);
        ue_safe_free(tls_keystore);
    }
}

bool ue_tls_keystore_verify_peer(ue_tls_keystore *tls_keystore) {
    return ue_tls_connection_verify_peer_certificate(tls_keystore->tls);
}
