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
#include <unknownecho/time/timer.h>
#include <unknownecho/crypto/api/key/public_key.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/crypto/api/key/asym_key.h>
#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/cipher/data_cipher.h>
#include <unknownecho/crypto/factory/rsa_asym_key_factory.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define CIPHER_ID   1
#define DECIPHER_ID 2

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size/*, i*/;
    ue_x509_certificate *certificate;
    ue_public_key *public_key;
    ue_private_key *private_key;
    ue_asym_key *asym_key;

    cipher_data = NULL;
    plain_data = NULL;
    decipher_data = NULL;
    certificate = NULL;
    public_key = NULL;
    private_key = NULL;
    asym_key = NULL;

    ue_init();

    if (!(plain_data = ue_bytes_create_from_string(argv[1]))) {
        ue_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    plain_data_size = strlen(argv[1]);

    ue_x509_certificate_load_from_file(argv[2], &certificate);

    public_key = ue_rsa_public_key_from_x509_certificate(certificate);

    private_key = ue_rsa_private_key_from_key_certificate(argv[3]);

    //asym_key = ue_rsa_asym_key_create(2048);


    ue_timer_start(CIPHER_ID);
    if (!cipher_plain_data(plain_data, plain_data_size, public_key, private_key, &cipher_data, &cipher_data_size, NULL)) {
        ue_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }
    ue_timer_stop(CIPHER_ID);

    ue_timer_start(DECIPHER_ID);
    if (!decipher_cipher_data(cipher_data, cipher_data_size, private_key, public_key, &decipher_data, &decipher_data_size)) {
        ue_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }
    ue_timer_stop(DECIPHER_ID);

    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        ue_logger_info("Plain data and decipher data match");
        ue_timer_total_print(CIPHER_ID, "cipher data");
        ue_timer_total_print(DECIPHER_ID, "decipher data");
    } else {
        ue_logger_error("Plain data and decipher data doesn't match");
    }

clean_up:
    ue_public_key_destroy(public_key);
    ue_private_key_destroy(private_key);
    ue_asym_key_destroy_all(asym_key);
    ue_safe_free(plain_data);
    ue_safe_free(cipher_data);
    ue_safe_free(decipher_data);
    ue_x509_certificate_destroy(certificate);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
