#ifndef UNKNOWNECHO_TLS_CONTEXT_H
#define UNKNOWNECHO_TLS_CONTEXT_H

#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/bool.h>

typedef struct ue_tls_context ue_tls_context;

ue_tls_context *ue_tls_context_create(ue_tls_method *method);

void ue_tls_context_destroy(ue_tls_context *context);

bool ue_tls_context_load_certificates(ue_tls_context *context, char *passphrase, char *ca_pk_path, char *pk_path, char *sk_path);

const void *ue_tls_context_get_impl(ue_tls_context *context);

#endif
