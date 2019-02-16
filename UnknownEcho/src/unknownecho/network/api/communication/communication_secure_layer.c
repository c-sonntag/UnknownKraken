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

#include <unknownecho/network/api/communication/communication_secure_layer.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <uecm/uecm.h>
#include <ei/ei.h>

#include <stdarg.h>
#include <string.h>

void *ue_communication_secure_layer_build_client(ue_communication_context *context, int count, ...) {
    void *secure_layer;
    va_list ap;
    char *keystore_path, *passphrase;
    uecm_x509_certificate **ca_certificates;
    int ca_certificate_count;

    ei_check_parameter_or_return(context);
    ei_check_parameter_or_return(count > 0);

    secure_layer = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        if (count != 4) {
            ei_stacktrace_push_msg("Specified number of argments doesn't fit with communication type SOCKET");
            return NULL;
        }
        va_start(ap, count);
        keystore_path = va_arg(ap, char *);
        passphrase = va_arg(ap, char *);
        ca_certificates = va_arg(ap, uecm_x509_certificate **);
        ca_certificate_count = va_arg(ap, int);
        if (!(secure_layer = (void *)uecm_tls_session_create_client(keystore_path, passphrase,
            ca_certificates, ca_certificate_count))) {
            ei_stacktrace_push_msg("Failed to create TLS session for client");
        }
        va_end(ap);
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
    }

    return secure_layer;
}

void *ue_communication_secure_layer_build_server(ue_communication_context *context, int count, ...) {
    void *secure_layer;
    va_list ap;
    char *keystore_path, *passphrase;
    uecm_x509_certificate **ca_certificates;
    int ca_certificate_count;

    ei_check_parameter_or_return(context);
    ei_check_parameter_or_return(count > 0);

    secure_layer = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        if (count != 4) {
            ei_stacktrace_push_msg("Specified number of argments doesn't fit with communication type SOCKET");
            return NULL;
        }
        va_start(ap, count);
        keystore_path = va_arg(ap, char *);
        passphrase = va_arg(ap, char *);
        ca_certificates = va_arg(ap, uecm_x509_certificate **);
        ca_certificate_count = va_arg(ap, int);
        if (!(secure_layer = (void *)uecm_tls_session_create_server(keystore_path, passphrase,
            ca_certificates, ca_certificate_count))) {
            ei_stacktrace_push_msg("Failed to create TLS session for server");
        }
        va_end(ap);
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
    }

    return secure_layer;
}

bool ue_communication_secure_layer_destroy(ue_communication_context *context, void *csl) {
    ei_check_parameter_or_return(context);
    ei_check_parameter_or_return(context->communication_type);

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        uecm_tls_session_destroy((uecm_tls_session *)csl);
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
        return false;
    }

    return true;
}

uecm_pkcs12_keystore *ue_communication_secure_layer_get_keystore(ue_communication_context *context, void *csl) {
    uecm_pkcs12_keystore *keystore;
    uecm_tls_session *tls_session;

    ei_check_parameter_or_return(context);
    ei_check_parameter_or_return(context->communication_type);
    ei_check_parameter_or_return(csl);

    keystore = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        tls_session = (uecm_tls_session *)csl;
        keystore = tls_session->keystore;
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
    }

    return keystore;
}
