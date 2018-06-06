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

#include <unknownecho/network/api/communication/communication_secure_layer.h>
#include <unknownecho/network/api/tls/tls_session.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <ei/ei.h>

#include <stdarg.h>
#include <string.h>

void *ue_communication_secure_layer_build_client(ue_communication_context *context, int count, ...) {
    void *secure_layer;
    va_list ap;
    char *keystore_path, *passphrase;
    ue_x509_certificate **ca_certificates;
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
        ca_certificates = va_arg(ap, ue_x509_certificate **);
        ca_certificate_count = va_arg(ap, int);
        if (!(secure_layer = (void *)ue_tls_session_create_client(keystore_path, passphrase,
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
    ue_x509_certificate **ca_certificates;
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
        ca_certificates = va_arg(ap, ue_x509_certificate **);
        ca_certificate_count = va_arg(ap, int);
        if (!(secure_layer = (void *)ue_tls_session_create_server(keystore_path, passphrase,
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
        ue_tls_session_destroy((ue_tls_session *)csl);
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
        return false;
    }

    return true;
}

ue_pkcs12_keystore *ue_communication_secure_layer_get_keystore(ue_communication_context *context, void *csl) {
    ue_pkcs12_keystore *keystore;
    ue_tls_session *tls_session;

    ei_check_parameter_or_return(context);
    ei_check_parameter_or_return(context->communication_type);
    ei_check_parameter_or_return(csl);

    keystore = NULL;

    if (strcmp(context->communication_type, "SOCKET") == 0) {
        tls_session = (ue_tls_session *)csl;
        keystore = tls_session->keystore;
    } else {
        ei_stacktrace_push_msg("Unknown communication type");
    }

    return keystore;
}
