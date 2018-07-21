/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
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
