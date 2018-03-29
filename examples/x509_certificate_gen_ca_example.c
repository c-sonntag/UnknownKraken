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
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/factory/x509_certificate_factory.h>

#include <stdio.h>

int main() {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;

    certificate = NULL;
    private_key = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    if (!ue_x509_certificate_generate_self_signed_ca("SWA", &certificate, &private_key)) {
        ue_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    if (!ue_x509_certificate_print_pair(certificate, private_key, "ca_out/cert.pem", "ca_out/key.pem", NULL)) {
        ue_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }

clean_up:
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    ue_uninit();
    return 0;
}
