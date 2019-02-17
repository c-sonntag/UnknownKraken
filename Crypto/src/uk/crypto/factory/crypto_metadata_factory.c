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

#include <uk/crypto/factory/crypto_metadata_factory.h>
#include <uk/crypto/factory/sym_key_factory.h>
#include <uk/crypto/factory/x509_certificate_factory.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/key/sym_key.h>
#include <uk/crypto/api/crypto_metadata.h>
#include <uk/crypto/defines.h>

#include <uk/utils/ei.h>

#include <uk/utils/ueum.h>

uk_crypto_crypto_metadata *uk_crypto_crypto_metadata_create_default() {
    uk_crypto_crypto_metadata *crypto_metadata;
    uk_crypto_x509_certificate *cipher_certificate, *signer_certificate;
    uk_crypto_private_key *cipher_private_key, *signer_private_key;
    const char *cipher_name, *digest_name;
    uk_crypto_sym_key *sym_key;

    crypto_metadata = uk_crypto_crypto_metadata_create_empty();
    cipher_certificate = NULL;
    signer_certificate = NULL;
    cipher_private_key = NULL;
    signer_private_key = NULL;
    cipher_name = NULL;
    digest_name = NULL;
    sym_key = NULL;

    if (!uk_crypto_x509_certificate_generate_self_signed_ca("CIPHER", &cipher_certificate, &cipher_private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate self signed CA for CIPHER");
        goto clean_up_fail;
    }

    if (!uk_crypto_x509_certificate_generate_self_signed_ca("SIGNER", &signer_certificate, &signer_private_key)) {
        uk_utils_stacktrace_push_msg("Failed to generate self signed CA for SIGNER");
        goto clean_up_fail;
    }

    if ((cipher_name = uk_utils_string_create_from(UnknownKrakenCrypto_DEFAULT_CIPHER_NAME)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get default cipher name");
        goto clean_up_fail;
    }

    if ((digest_name = uk_utils_string_create_from(UnknownKrakenCrypto_DEFAULT_DIGEST_NAME)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get default digest name");
        goto clean_up_fail;
    }

    if ((sym_key = uk_crypto_sym_key_create_random()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to generate random sym key");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_cipher_certificate(crypto_metadata, cipher_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to set cipher certificate to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_signer_certificate(crypto_metadata, signer_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to set signer certificate to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_cipher_private_key(crypto_metadata, cipher_private_key)) {
        uk_utils_stacktrace_push_msg("Failed to set cipher private key to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_signer_private_key(crypto_metadata, signer_private_key)) {
        uk_utils_stacktrace_push_msg("Failed to set signer private key to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_cipher_name(crypto_metadata, cipher_name)) {
        uk_utils_stacktrace_push_msg("Failed to set cipher name to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_digest_name(crypto_metadata, digest_name)) {
        uk_utils_stacktrace_push_msg("Failed to set digest name to crypto metadata");
        goto clean_up_fail;
    }

    if (!uk_crypto_crypto_metadata_set_sym_key(crypto_metadata, sym_key)) {
        uk_utils_stacktrace_push_msg("Failed to set sym key to crypto metadata");
        goto clean_up_fail;
    }

    return crypto_metadata;

clean_up_fail:
    uk_crypto_x509_certificate_destroy(cipher_certificate);
    uk_crypto_x509_certificate_destroy(signer_certificate);
    uk_crypto_private_key_destroy(cipher_private_key);
    uk_crypto_private_key_destroy(signer_private_key);
    uk_crypto_crypto_metadata_destroy(crypto_metadata);
    uk_utils_safe_free(cipher_name);
    uk_utils_safe_free(digest_name);
    uk_crypto_sym_key_destroy(sym_key);
    return NULL;
}

uk_crypto_crypto_metadata *uk_crypto_crypto_metadata_write_if_not_exist(const char *private_folder, const char *
    certificates_folder, const char *uid, const char *password) {

    uk_crypto_crypto_metadata *our_crypto_metadata;

    uk_utils_check_parameter_or_return(private_folder);
    uk_utils_check_parameter_or_return(certificates_folder);
    uk_utils_check_parameter_or_return(uid);
    uk_utils_check_parameter_or_return(password);

    our_crypto_metadata = NULL;

    uk_utils_logger_trace("Checking if crypto metadata already exists...");
    if (!uk_crypto_crypto_metadata_exists(private_folder, uid)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("Failed to check if crypto metadata already exists");
            uk_utils_stacktrace_clean_up();
        }
        if ((our_crypto_metadata = uk_crypto_crypto_metadata_create_default()) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to create random crypto metadata");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
        uk_utils_logger_trace("Writing crypto metadata...");
        if (!uk_crypto_crypto_metadata_write(our_crypto_metadata, private_folder, uid, password)) {
            uk_utils_stacktrace_push_msg("Failed to write our crypto metadata in secure files");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    } else {
        if ((our_crypto_metadata = uk_crypto_crypto_metadata_create_empty()) == NULL) {
            uk_utils_stacktrace_push_msg("Failed to create empty crypto metadata");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
        uk_utils_logger_trace("Crypto metadata already exists");
        if (!uk_crypto_crypto_metadata_read(our_crypto_metadata, private_folder, uid, password)) {
            uk_utils_stacktrace_push_msg("Failed to read our crypto metadata");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    }

    uk_utils_logger_trace("Checking if certificates already exists...");
    if (!uk_crypto_crypto_metadata_certificates_exists(certificates_folder, uid)) {
        if (uk_utils_stacktrace_is_filled()) {
            uk_utils_logger_stacktrace("Failed to check if certificates already exists");
            uk_utils_stacktrace_clean_up();
        }
        uk_utils_logger_trace("Writing certificates...");
        if (!uk_crypto_crypto_metadata_write_certificates(our_crypto_metadata, certificates_folder, uid)) {
            uk_utils_stacktrace_push_msg("Failed to write our certificates in public folder");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    } else {
        uk_utils_logger_trace("Certificates already exists");
        uk_utils_logger_trace("Reading certificates...");
        if (!uk_crypto_crypto_metadata_read_certificates(our_crypto_metadata, certificates_folder, uid)) {
            uk_utils_stacktrace_push_msg("Failed to read certificates");
            uk_crypto_crypto_metadata_destroy_all(our_crypto_metadata);
            return NULL;
        }
    }

    return our_crypto_metadata;
}
