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
#include <unknownecho/bool.h>
#include <unknownecho/alloc.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_parameters.h>
#include <unknownecho/crypto/api/certificate/x509_certificate_generation.h>
#include <unknownecho/crypto/api/certificate/x509_csr.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

bool generate_certificate(ue_x509_certificate **certificate, ue_private_key **private_key) {
    bool result;
    ue_x509_certificate_parameters *parameters;

	result = false;
	parameters = NULL;

	if (!(parameters = ue_x509_certificate_parameters_create())) {
		ue_stacktrace_push_msg("Failed to create x509 parameters structure");
		return false;
	}

    if (!ue_x509_certificate_parameters_set_country(parameters, "FR")) {
		ue_stacktrace_push_msg("Failed to set C to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_common_name(parameters, "SWA")) {
		ue_stacktrace_push_msg("Failed to set CN to x509 parameters");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_ca_type(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as ca type");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_subject_key_identifier_as_hash(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate subject key identifier as hash");
		goto clean_up;
	}

    if (!ue_x509_certificate_parameters_set_self_signed(parameters)) {
		ue_stacktrace_push_msg("Failed to set certificate as self signed");
		goto clean_up;
	}

    if (!ue_x509_certificate_generate(parameters, certificate, private_key)) {
		ue_stacktrace_push_msg("Failed to generate certificate and relative private key");
		goto clean_up;
	}

    result = true;

clean_up:
    ue_x509_certificate_parameters_destroy(parameters);
    return result;
}

int main() {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    ue_x509_csr *csr;
    char *csr_string;

    ue_init();

    certificate = NULL;
    private_key = NULL;
    csr = NULL;
    csr_string = NULL;

    if (!generate_certificate(&certificate, &private_key)) {
        ue_stacktrace_push_msg("Failed to generate x509 certificate and private key");
        goto clean_up;
    }

    if (!(csr = ue_x509_csr_create(certificate, private_key))) {
        ue_stacktrace_push_msg("Failed to create x509 CRS from certificate and private key");
        goto clean_up;
    }

    ue_logger_info("Print CRS :");
    if (!ue_x509_csr_print(csr, stdout)) {
        ue_stacktrace_push_msg("Failed to print x509 CRS");
        goto clean_up;
    }

    ue_logger_info("Convert x509 CRS to string...");
    if (!(csr_string = ue_x509_csr_to_string(csr))) {
        ue_stacktrace_push_msg("Failed to convert x509 CRS to string");
        goto clean_up;
    }

    ue_logger_info("x509 CRS :\n%s", csr_string);

clean_up:
    ue_x509_certificate_destroy(certificate);
    ue_private_key_destroy(private_key);
    ue_x509_csr_destroy(csr);
    ue_safe_free(csr_string);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
