/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of UnknownEchoLib.                                        *
 *                                                                             *
 *   UnknownEchoLib is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   UnknownEchoLib is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with UnknownEchoLib.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

#include <unknownecho/network/api/tls/tls_method.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/crypto/impl/errorHandling/openssl_error_handling.h>

#include <openssl/ssl.h>

struct ue_tls_method {
    const SSL_METHOD *impl;
};

ue_tls_method *ue_tls_method_create_client() {
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

ue_tls_method *ue_tls_method_create_server() {
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
