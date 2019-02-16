/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
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

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stdio.h>

#define CERTIFICATE_PATH "out/cert.pem"
#define PRIVATE_KEY_PATH "out/key.pem"
#define CN               "SWA"

int main() {
    uecm_x509_certificate *certificate;
    uecm_private_key *private_key;

    certificate = NULL;
    private_key = NULL;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_debug("CERTIFICATE_PATH=%s", CERTIFICATE_PATH);
    ei_logger_debug("PRIVATE_KEY_PATH=%s", PRIVATE_KEY_PATH);
    ei_logger_debug("CN=%s", CN);

    ei_logger_info("Generating self signed x509 certificate and private key...");
    if (!uecm_x509_certificate_generate_self_signed_ca(CN, &certificate, &private_key)) {
        ei_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    ei_logger_info("Writing to file self signed x509 certificate and private key...");
    if (!uecm_x509_certificate_print_pair(certificate, private_key, CERTIFICATE_PATH, PRIVATE_KEY_PATH, NULL)) {
        ei_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_x509_certificate_destroy(certificate);
    uecm_private_key_destroy(private_key);
    uecm_uninit();
    ei_uninit();
    return 0;
}
