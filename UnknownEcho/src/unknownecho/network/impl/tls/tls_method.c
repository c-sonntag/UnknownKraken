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

#include <unknownecho/network/api/tls/tls_method.h>
#include <ueum/ueum.h>
#include <uecm/uecm.h>

#include <openssl/ssl.h>

struct uecm_tls_method {
    const SSL_METHOD *impl;
};

uecm_tls_method *uecm_tls_method_create_client() {
    uecm_tls_method *method;
    char *error_buffer;

    method = NULL;

    ueum_safe_alloc(method, uecm_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_client_method())) {
        uecm_openssl_error_handling(error_buffer, "TLSv1_client_method");
        ueum_safe_free(method);
        return NULL;
    }

    return method;
}

uecm_tls_method *uecm_tls_method_create_server() {
    uecm_tls_method *method;
    char *error_buffer;

    method = NULL;

    ueum_safe_alloc(method, uecm_tls_method, 1);
    method->impl = NULL;

    if (!(method->impl = TLS_server_method())) {
        uecm_openssl_error_handling(error_buffer, "TLSv1_server_method");
        ueum_safe_free(method);
        return NULL;
    }

    return method;
}

void uecm_tls_method_destroy(uecm_tls_method *method) {
    ueum_safe_free(method);
}

const void *uecm_tls_method_get_impl(uecm_tls_method *method) {
    return method->impl;
}
