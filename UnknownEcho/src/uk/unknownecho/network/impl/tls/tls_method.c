/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

#include <uk/unknownecho/network/api/tls/tls_method.h>
#include <uk/utils/ueum.h>
#include <uk/crypto/uecm.h>

#include <openssl/ssl.h>

struct uk_crypto_tls_method {
    const SSL_METHOD *impl;
};

uk_crypto_tls_method *uk_crypto_tls_method_create_client() {
    uk_crypto_tls_method *method;
    char *error_buffer;

    method = NULL;

    uk_utils_safe_alloc(method, uk_crypto_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_client_method())) {
        uk_crypto_openssl_error_handling(error_buffer, "TLSv1_client_method");
        uk_utils_safe_free(method);
        return NULL;
    }

    return method;
}

uk_crypto_tls_method *uk_crypto_tls_method_create_server() {
    uk_crypto_tls_method *method;
    char *error_buffer;

    method = NULL;

    uk_utils_safe_alloc(method, uk_crypto_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_server_method())) {
        uk_crypto_openssl_error_handling(error_buffer, "TLSv1_server_method");
        uk_utils_safe_free(method);
        return NULL;
    }

    return method;
}

void uk_crypto_tls_method_destroy(uk_crypto_tls_method *method) {
    uk_utils_safe_free(method);
}

const void *uk_crypto_tls_method_get_impl(uk_crypto_tls_method *method) {
    return method->impl;
}
