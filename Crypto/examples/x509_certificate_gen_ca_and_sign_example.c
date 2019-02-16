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

#define CA_CERTIFICATE_PATH "out/ca_cert.pem"
#define CA_PRIVATE_KEY_PATH "out/ca_key.pem"
#define CERTIFICATE_PATH    "out/cert.pem"
#define PRIVATE_KEY_PATH    "out/key.pem"
#define CN                  "SWA"

int main() {
    uecm_x509_certificate *ca_certificate, *read_ca_certificate, *certificate;
    uecm_private_key *ca_private_key, *read_ca_private_key, *private_key;

    ca_certificate = NULL;
    ca_private_key = NULL;
    read_ca_certificate = NULL;
    read_ca_private_key = NULL;
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

    ei_logger_debug("CA_CERTIFICATE_PATH=%s", CA_CERTIFICATE_PATH);
    ei_logger_debug("CA_PRIVATE_KEY_PATH=%s", CA_PRIVATE_KEY_PATH);
    ei_logger_debug("CERTIFICATE_PATH=%s", CERTIFICATE_PATH);
    ei_logger_debug("PRIVATE_KEY_PATH=%s", PRIVATE_KEY_PATH);
    ei_logger_debug("CN=%s", CN);

    ei_logger_info("Generating self signed CA key pair...");
    if (!uecm_x509_certificate_generate_self_signed_ca(CN, &ca_certificate, &ca_private_key)) {
        ei_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    ei_logger_info("Writing self signed CA key pair...");
    if (!uecm_x509_certificate_print_pair(ca_certificate, ca_private_key, CA_CERTIFICATE_PATH, CA_PRIVATE_KEY_PATH, NULL)) {
        ei_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    ei_logger_info("Loading self signed CA key pair from files...");
    if (!uecm_x509_certificate_load_from_files(CA_CERTIFICATE_PATH, CA_PRIVATE_KEY_PATH, NULL, &read_ca_certificate, &read_ca_private_key)) {
        ei_logger_error("Failed to load ca certificate and private from files");
        goto clean_up;
    }

    ei_logger_info("Generating signed certificate and private key from CA signed key pair...");
    if (!uecm_x509_certificate_generate_signed(read_ca_certificate, read_ca_private_key, CN, &certificate, &private_key)) {
        ei_logger_error("Failed to generate certificate signed by CA");
        goto clean_up;
    }

    ei_logger_info("Writing signed certificate and private key...");
    if (!uecm_x509_certificate_print_pair(certificate, private_key, CERTIFICATE_PATH, PRIVATE_KEY_PATH, NULL)) {
        ei_logger_error("Failed to print signed certificate and private key to files");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_x509_certificate_destroy(ca_certificate);
    uecm_private_key_destroy(ca_private_key);
    uecm_x509_certificate_destroy(read_ca_certificate);
    uecm_private_key_destroy(read_ca_private_key);
    uecm_x509_certificate_destroy(certificate);
    uecm_private_key_destroy(private_key);
    uecm_uninit();
    ei_uninit();
    return 0;
}
