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

#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>

#include <stdio.h>

int main() {
    ue_x509_certificate *ca_certificate, *read_ca_certificate, *certificate;
    ue_private_key *ca_private_key, *read_ca_private_key, *private_key;

    ca_certificate = NULL;
    ca_private_key = NULL;
    read_ca_certificate = NULL;
    read_ca_private_key = NULL;
    certificate = NULL;
    private_key = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!ue_x509_certificate_generate_self_signed_ca("SWA", &ca_certificate, &ca_private_key)) {
        ue_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "out/ca_cert.pem", "out/ca_key.pem")) {
        ue_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    if (!ue_x509_certificate_load_from_files("out/ca_cert.pem", "out/ca_key.pem", NULL, &read_ca_certificate, &read_ca_private_key)) {
        ue_logger_error("Failed to load ca certificate and private from files");
        goto clean_up;
    }

    if (!ue_x509_certificate_generate_signed(read_ca_certificate, read_ca_private_key, "SWA", &certificate, &private_key)) {
        ue_logger_error("Failed to generate certificate signed by CA");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(ca_certificate, ca_private_key, "out/cert.pem", "out/key.pem")) {
        ue_logger_error("Failed to print signed certificate and private key to files");
        goto clean_up;
    }

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

clean_up:
    ue_x509_certificate_destroy(ca_certificate);
    ue_private_key_destroy(ca_private_key);
    ue_x509_certificate_destroy(read_ca_certificate);
    ue_private_key_destroy(read_ca_private_key);
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    ue_uninit();
    return 0;
}
