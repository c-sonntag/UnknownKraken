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

#include <uk/crypto/uecm.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stdio.h>

#define CERTIFICATE_PATH "out/cert.pem"
#define PRIVATE_KEY_PATH "out/key.pem"
#define CN               "SWA"

int main() {
    uk_crypto_x509_certificate *certificate;
    uk_crypto_private_key *private_key;

    certificate = NULL;
    private_key = NULL;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    uk_utils_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uk_crypto_init()) {
        uk_utils_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    uk_utils_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    uk_utils_logger_debug("CERTIFICATE_PATH=%s", CERTIFICATE_PATH);
    uk_utils_logger_debug("PRIVATE_KEY_PATH=%s", PRIVATE_KEY_PATH);
    uk_utils_logger_debug("CN=%s", CN);

    uk_utils_logger_info("Generating self signed x509 certificate and private key...");
    if (!uk_crypto_x509_certificate_generate_self_signed_ca(CN, &certificate, &private_key)) {
        uk_utils_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    uk_utils_logger_info("Writing to file self signed x509 certificate and private key...");
    if (!uk_crypto_x509_certificate_print_pair(certificate, private_key, CERTIFICATE_PATH, PRIVATE_KEY_PATH, NULL)) {
        uk_utils_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    uk_utils_logger_info("Succeed !");

clean_up:
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_crypto_x509_certificate_destroy(certificate);
    uk_crypto_private_key_destroy(private_key);
    uk_crypto_uninit();
    uk_utils_uninit();
    return 0;
}
