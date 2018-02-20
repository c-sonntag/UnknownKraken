#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/ssl.h>

struct ue_tls_method {
    const SSL_METHOD *impl;
};

ue_tls_method *ue_tls_method_create_v1_client() {
    ue_tls_method *method;
    char *error_buffer;

    ue_safe_alloc(method, ue_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_client_method())) {
        ue_openssl_error_handling(error_buffer, "TLSv1_client_method");
        ue_safe_free(method);
        return NULL;
    }

    return method;
}

ue_tls_method *ue_tls_method_create_v1_server() {
    ue_tls_method *method;
    char *error_buffer;

    ue_safe_alloc(method, ue_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_server_method())) {
        ue_openssl_error_handling(error_buffer, "TLSv1_server_method");
        ue_safe_free(method);
        return NULL;
    }

    return method;
}

void ue_tls_method_destroy(ue_tls_method *method) {
    ue_safe_free(method);
}

const void *ue_tls_method_get_impl(ue_tls_method *method) {
    return method->impl;
}
