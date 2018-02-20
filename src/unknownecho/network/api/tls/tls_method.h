#ifndef UNKNOWNECHO_TLS_METHOD_H
#define UNKNOWNECHO_TLS_METHOD_H

typedef struct ue_tls_method ue_tls_method;

ue_tls_method *ue_tls_method_create_v1_client();

ue_tls_method *ue_tls_method_create_v1_server();

void ue_tls_method_destroy(ue_tls_method *method);

const void *ue_tls_method_get_impl(ue_tls_method *method);

#endif
