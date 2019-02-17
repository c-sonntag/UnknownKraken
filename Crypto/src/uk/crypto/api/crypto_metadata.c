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

#include <uk/crypto/api/crypto_metadata.h>
#include <uk/crypto/api/key/sym_key.h>
#include <uk/crypto/api/key/public_key.h>
#include <uk/crypto/api/key/private_key.h>
#include <uk/crypto/api/encryption/sym_encrypter.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/factory/pkcs12_keystore_factory.h>
#include <uk/crypto/factory/sym_encrypter_factory.h>
#include <uk/crypto/factory/sym_key_factory.h>
#include <uk/crypto/factory/rsa_asym_key_factory.h>
#include <uk/crypto/utils/crypto_random.h>
#include <uk/crypto/utils/friendly_name.h>

#include <uk/utils/ueum.h>

#include <uk/utils/ei.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>


static bool crypto_metadata_write_sym(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid,
    const char *password);

static bool crypto_metadata_write_asym(const char *folder_name, const char *uid,
    const char *password, uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key, const char *keystore_type);

static bool crypto_metadata_read_sym(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid,
    const char *password);

static bool crypto_metadata_read_asym(const char *folder_name, const char *uid,
    const char *password, const char *keystore_type, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key,
    uk_crypto_public_key **public_key);

uk_crypto_crypto_metadata *uk_crypto_crypto_metadata_create_empty() {
    uk_crypto_crypto_metadata *metadata;

    metadata = NULL;

    uk_utils_safe_alloc(metadata, uk_crypto_crypto_metadata, 1);
    metadata->cipher_certificate = NULL;
    metadata->signer_certificate = NULL;
    metadata->cipher_name = NULL;
    metadata->cipher_pk = NULL;
    metadata->cipher_sk = NULL;
    metadata->digest_name = NULL;
    metadata->signer_pk = NULL;
    metadata->signer_sk = NULL;
    metadata->sym_key = NULL;

    return metadata;
}

void uk_crypto_crypto_metadata_destroy(uk_crypto_crypto_metadata *metadata) {
    if (metadata) {
        uk_utils_safe_free(metadata->cipher_name);
        uk_utils_safe_free(metadata->digest_name);
        uk_utils_safe_free(metadata);
    }
}

void uk_crypto_crypto_metadata_destroy_all(uk_crypto_crypto_metadata *metadata) {
    if (metadata) {
        uk_utils_safe_free(metadata->cipher_name);
        uk_utils_safe_free(metadata->digest_name);
        uk_crypto_x509_certificate_destroy(metadata->cipher_certificate);
        uk_crypto_x509_certificate_destroy(metadata->signer_certificate);
        uk_crypto_public_key_destroy(metadata->cipher_pk);
        uk_crypto_private_key_destroy(metadata->cipher_sk);
        uk_crypto_public_key_destroy(metadata->signer_pk);
        uk_crypto_private_key_destroy(metadata->signer_sk);
        uk_crypto_sym_key_destroy(metadata->sym_key);
        uk_utils_safe_free(metadata);
    }
}

uk_crypto_sym_key *uk_crypto_crypto_metadata_get_sym_key(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->sym_key;
}

bool uk_crypto_crypto_metadata_set_sym_key(uk_crypto_crypto_metadata *metadata, uk_crypto_sym_key *key) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(key);

    metadata->sym_key = key;

    return true;
}

uk_crypto_x509_certificate *uk_crypto_crypto_metadata_get_cipher_certificate(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->cipher_certificate;
}

bool uk_crypto_crypto_metadata_set_cipher_certificate(uk_crypto_crypto_metadata *metadata, uk_crypto_x509_certificate *certificate) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(certificate);

    metadata->cipher_certificate = certificate;
    if (metadata->cipher_pk) {
        uk_crypto_public_key_destroy(metadata->cipher_pk);
    }
    if ((metadata->cipher_pk = uk_crypto_rsa_public_key_from_x509_certificate(certificate)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract RSA public key from specified certificate");
        return false;
    }

    return true;
}

uk_crypto_public_key *uk_crypto_crypto_metadata_get_cipher_public_key(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->cipher_pk;
}

uk_crypto_private_key *uk_crypto_crypto_metadata_get_cipher_private_key(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->cipher_sk;
}

bool uk_crypto_crypto_metadata_set_cipher_private_key(uk_crypto_crypto_metadata *metadata, uk_crypto_private_key *sk) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(sk);

    metadata->cipher_sk = sk;

    return true;
}

uk_crypto_x509_certificate *uk_crypto_crypto_metadata_get_signer_certificate(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->signer_certificate;
}

bool uk_crypto_crypto_metadata_set_signer_certificate(uk_crypto_crypto_metadata *metadata, uk_crypto_x509_certificate *certificate) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(certificate);

    metadata->signer_certificate = certificate;
    if (metadata->signer_pk) {
        uk_crypto_public_key_destroy(metadata->signer_pk);
    }
    if ((metadata->signer_pk = uk_crypto_rsa_public_key_from_x509_certificate(certificate)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract RSA public key from specified certificate");
        return false;
    }

    return true;
}

uk_crypto_public_key *uk_crypto_crypto_metadata_get_signer_public_key(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->signer_pk;
}

uk_crypto_private_key *uk_crypto_crypto_metadata_get_signer_private_key(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->signer_sk;
}

bool uk_crypto_crypto_metadata_set_signer_private_key(uk_crypto_crypto_metadata *metadata, uk_crypto_private_key *sk) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(sk);

    metadata->signer_sk = sk;

    return true;
}

const char *uk_crypto_crypto_metadata_get_cipher_name(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->cipher_name;
}

bool uk_crypto_crypto_metadata_set_cipher_name(uk_crypto_crypto_metadata *metadata, const char *cipher_name) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(cipher_name);

    metadata->cipher_name = cipher_name;

    return true;
}

const char *uk_crypto_crypto_metadata_get_digest_name(uk_crypto_crypto_metadata *metadata) {
    uk_utils_check_parameter_or_return(metadata);

    return metadata->digest_name;
}

bool uk_crypto_crypto_metadata_set_digest_name(uk_crypto_crypto_metadata *metadata, const char *digest_name) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(digest_name);

    metadata->digest_name = digest_name;

    return true;
}

bool uk_crypto_crypto_metadata_certificates_exists(const char *folder_name, const char *uid) {
    bool result;
    const char *cipher_certificate_file_name, *signer_certificate_file_name;

    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);

    if (!uk_utils_is_dir_exists(folder_name)) {
        return false;
    }

    result = false;
    cipher_certificate_file_name = NULL;
    signer_certificate_file_name = NULL;

    if ((cipher_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_CIPHER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build cipher certificate file name");
        return false;
    }

    if ((signer_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_SIGNER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build signer certificate file name");
        goto clean_up;
    }

    if (uk_utils_is_file_exists(cipher_certificate_file_name) ||
        uk_utils_is_file_exists(signer_certificate_file_name)) {
        result = true;
    } else {
        result = false;
    }

clean_up:
    uk_utils_safe_free(cipher_certificate_file_name);
    uk_utils_safe_free(signer_certificate_file_name);
    return result;
}

bool uk_crypto_crypto_metadata_exists(const char *folder_name, const char *uid) {
    bool result;
    const char *sym_file_name, *asym_cipher_file_name, *asym_signer_file_name;

    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);

    if (!uk_utils_is_dir_exists(folder_name)) {
        return false;
    }

    result = false;
    sym_file_name = NULL;
    asym_cipher_file_name = NULL;
    asym_signer_file_name = NULL;

    if ((sym_file_name = uk_utils_strcat_variadic("sss", folder_name, "/", uid, "_sym")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name for sym crypto metadata");
        goto clean_up;
    }

    if ((asym_cipher_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_asym_CIPHER")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name with name '%s' for keystore 'CIPHER'", uid);
        goto clean_up;
    }

    if ((asym_signer_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_asym_SIGNER")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name with name '%s' for keystore 'SIGNER'", uid);
        goto clean_up;
    }

    if (uk_utils_is_file_exists(sym_file_name) ||
        uk_utils_is_file_exists(asym_cipher_file_name) ||
        uk_utils_is_file_exists(asym_signer_file_name)) {

        result = true;
    } else {
        result = false;
    }

clean_up:
    uk_utils_safe_free(sym_file_name);
    uk_utils_safe_free(asym_cipher_file_name);
    uk_utils_safe_free(asym_signer_file_name);
    return result;
}

bool uk_crypto_crypto_metadata_write_certificates(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid) {
    bool result;
    const char *cipher_certificate_file_name, *signer_certificate_file_name;
    FILE *cipher_certificate_fd, *signer_certificate_fd;

    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);

    if (!metadata->cipher_certificate) {
        uk_utils_stacktrace_push_msg("Cipher certificate ptr is null");
        return false;
    }

    if (!metadata->signer_certificate) {
        uk_utils_stacktrace_push_msg("Signer certificate ptr is null");
        return false;
    }

    result = false;
    cipher_certificate_file_name = NULL;
    signer_certificate_file_name = NULL;
    cipher_certificate_fd = NULL;
    signer_certificate_fd = NULL;

    if (!uk_utils_is_dir_exists(folder_name)) {
        uk_utils_logger_trace("Folder '%s' doesn't exists. Creating the path recursively...", folder_name);
        if (!uk_utils_create_folder(folder_name)) {
            uk_utils_stacktrace_push_msg("Failed to create folder path '%s'", folder_name);
            return false;
        }
    } else {
        uk_utils_logger_trace("Folder '%s' exists", folder_name);
    }

    if ((cipher_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_CIPHER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build cipher certificate file name");
        return false;
    }

    if ((signer_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_SIGNER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build signer certificate file name");
        goto clean_up;
    }

    if ((cipher_certificate_fd = fopen(cipher_certificate_file_name, "wb")) == NULL) {
       uk_utils_stacktrace_push_errno();
       goto clean_up;
    }

    if ((signer_certificate_fd = fopen(signer_certificate_file_name, "wb")) == NULL) {
        uk_utils_stacktrace_push_errno();
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_print(metadata->cipher_certificate, cipher_certificate_fd)) {
        uk_utils_stacktrace_push_msg("Failed to print cipher certificate at path '%s'", cipher_certificate_file_name);
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_print(metadata->signer_certificate, signer_certificate_fd)) {
        uk_utils_stacktrace_push_msg("Failed to print signer certificate at path '%s'", signer_certificate_file_name);
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(cipher_certificate_file_name);
    uk_utils_safe_free(signer_certificate_file_name);
    uk_utils_safe_fclose(cipher_certificate_fd);
    uk_utils_safe_fclose(signer_certificate_fd);
    return result;
}

bool uk_crypto_crypto_metadata_read_certificates(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid) {
    bool result;
    uk_crypto_x509_certificate *cipher_certificate, *signer_certificate;
    const char *cipher_certificate_file_name, *signer_certificate_file_name;

    result = false;
    cipher_certificate = NULL;
    signer_certificate = NULL;
    cipher_certificate_file_name = NULL;
    signer_certificate_file_name = NULL;

    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);

    if (!uk_utils_is_dir_exists(folder_name)) {
        uk_utils_stacktrace_push_msg("Specified folder '%s' doesn't exist", folder_name);
        return false;
    }

    if ((cipher_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_CIPHER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build cipher certificate file name");
        return false;
    }

    if ((signer_certificate_file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_SIGNER.pem")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build signer certificate file name");
        goto clean_up;
    }

    if (!uk_utils_is_file_exists(cipher_certificate_file_name)) {
        uk_utils_stacktrace_push_msg("File '%s' doesn't exist", cipher_certificate_file_name);
        goto clean_up;
    }

    if (!uk_utils_is_file_exists(signer_certificate_file_name)) {
        uk_utils_stacktrace_push_msg("File '%s' doesn't exist", signer_certificate_file_name);
        goto clean_up;
    }

    if (!uk_crypto_x509_certificate_load_from_file(cipher_certificate_file_name, &cipher_certificate)) {
        uk_utils_stacktrace_push_msg("Failed to load certificate from file '%s'", cipher_certificate_file_name);
        goto clean_up;
    }
    if (!uk_crypto_x509_certificate_load_from_file(signer_certificate_file_name, &signer_certificate)) {
        uk_crypto_x509_certificate_destroy(cipher_certificate);
        uk_utils_stacktrace_push_msg("Failed to load certificate from file '%s'", signer_certificate_file_name);
        goto clean_up;
    }

    if (!uk_crypto_crypto_metadata_set_cipher_certificate(metadata, cipher_certificate)) {
        uk_crypto_x509_certificate_destroy(cipher_certificate);
        uk_crypto_x509_certificate_destroy(signer_certificate);
        uk_utils_stacktrace_push_msg("Failed to set cipher certificate to crypto metadata");
        goto clean_up;
    }
    if (!uk_crypto_crypto_metadata_set_signer_certificate(metadata, signer_certificate)) {
        uk_crypto_x509_certificate_destroy(cipher_certificate);
        uk_crypto_x509_certificate_destroy(signer_certificate);
        uk_utils_stacktrace_push_msg("Failed to set signer certificate to crypto metadata");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(cipher_certificate_file_name);
    uk_utils_safe_free(signer_certificate_file_name);
    return result;
}

bool uk_crypto_crypto_metadata_write(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid,
    const char *password) {

    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);
    uk_utils_check_parameter_or_return(password);

    if (!uk_utils_is_dir_exists(folder_name)) {
        uk_utils_logger_trace("Folder '%s' doesn't exists. Creating the path recursively...", folder_name);
        if (!uk_utils_create_folder(folder_name)) {
            uk_utils_stacktrace_push_msg("Failed to create folder path '%s'", folder_name);
            return false;
        }
    } else {
        uk_utils_logger_trace("Folder '%s' exists", folder_name);
    }

    if (!crypto_metadata_write_asym(folder_name, uid, password, metadata->cipher_certificate, metadata->cipher_sk, "CIPHER")) {
        uk_utils_stacktrace_push_msg("Failed to write aysm cipher crypto metadata");
        return false;
    }

    if (!crypto_metadata_write_asym(folder_name, uid, password, metadata->signer_certificate, metadata->signer_sk, "SIGNER")) {
        uk_utils_stacktrace_push_msg("Failed to write aysm signer crypto metadata");
        return false;
    }

    if (!crypto_metadata_write_sym(metadata, folder_name, uid, password)) {
        uk_utils_stacktrace_push_msg("Failed to write sym crypto metadata");
        return false;
    }

    return true;
}

bool uk_crypto_crypto_metadata_read(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password) {
    uk_utils_check_parameter_or_return(metadata);
    uk_utils_check_parameter_or_return(folder_name);
    uk_utils_check_parameter_or_return(uid);
    uk_utils_check_parameter_or_return(password);

    if (!uk_utils_is_dir_exists(folder_name)) {
        uk_utils_stacktrace_push_msg("Specified folder 's' doesn't exist", folder_name);
        return false;
    }

    if (!crypto_metadata_read_sym(metadata, folder_name, uid, password)) {
        uk_utils_stacktrace_push_msg("Failed to read sym crypto metadata at '%s'", folder_name);
        return false;
    }

    if (!crypto_metadata_read_asym(folder_name, uid, password, "CIPHER",
        &metadata->cipher_certificate, &metadata->cipher_sk, &metadata->cipher_pk)) {

        uk_utils_stacktrace_push_msg("Failed to read cipher asym crypto metadata at '%s'", folder_name);
        return false;
    }

    if (!crypto_metadata_read_asym(folder_name, uid, password, "SIGNER",
        &metadata->signer_certificate, &metadata->signer_sk, &metadata->signer_pk)) {

        uk_utils_stacktrace_push_msg("Failed to read signer asym crypto metadata at '%s'", folder_name);
        return false;
    }

    return true;
}

static bool crypto_metadata_write_sym(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid, const char *password) {
    bool result;
    uk_crypto_sym_encrypter *sym_encrypter;
    uk_utils_byte_stream *stream;
    unsigned char *iv, *cipher_data;
    size_t cipher_data_size;
    const char *file_name;
    int iv_size;

    result = false;
    sym_encrypter = NULL;
    stream = uk_utils_byte_stream_create();
    iv = NULL;
    cipher_data = NULL;
    file_name = NULL;
    iv_size = 16;

    if (!metadata->sym_key && !metadata->digest_name && !metadata->cipher_name) {
        uk_utils_logger_trace("No sym crypto metadata to proceed");
        return true;
    }

    if ((sym_encrypter = uk_crypto_sym_encrypter_default_create(uk_crypto_sym_key_create_from_string(password))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to ");
        goto clean_up;
    }

    if ((file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_sym")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name for sym crypto metadata");
        goto clean_up;
    }

    if (metadata->sym_key) {
        uk_utils_byte_writer_append_int(stream, (int)metadata->sym_key->size);
    } else {
        uk_utils_byte_writer_append_int(stream, 0);
    }

    if (metadata->digest_name) {
        uk_utils_byte_writer_append_int(stream, (int)strlen(metadata->digest_name));
    } else {
        uk_utils_byte_writer_append_int(stream, 0);
    }

    if (metadata->cipher_name) {
        uk_utils_byte_writer_append_int(stream, (int)strlen(metadata->cipher_name));
    } else {
        uk_utils_byte_writer_append_int(stream, 0);
    }

    if (metadata->sym_key) {
        uk_utils_byte_writer_append_bytes(stream, metadata->sym_key->data, metadata->sym_key->size);
    }

    if (metadata->digest_name) {
        uk_utils_byte_writer_append_string(stream, metadata->digest_name);
    }

    if (metadata->cipher_name) {
        uk_utils_byte_writer_append_string(stream, metadata->cipher_name);
    }

    uk_utils_safe_alloc(iv, unsigned char, iv_size);

    if (!uk_crypto_crypto_random_bytes(iv, iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to generate crypto random bytes for IV");
        goto clean_up;
    }

    if (!uk_crypto_sym_encrypter_encrypt(sym_encrypter, uk_utils_byte_stream_get_data(stream), uk_utils_byte_stream_get_size(stream),
        iv, &cipher_data, &cipher_data_size)) {

        uk_utils_stacktrace_push_msg("Failed to encrypt stream with sym data");
        goto clean_up;
    }

    uk_utils_byte_stream_clean_up(stream);
    uk_utils_byte_stream_set_position(stream, 0);
    if (!uk_utils_byte_writer_append_int(stream, iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write iv size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, iv, iv_size)) {
        uk_utils_stacktrace_push_msg("Failed to write iv to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_int(stream, (int)cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data size to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_writer_append_bytes(stream, cipher_data, cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to write cipher data to stream");
        goto clean_up;
    }

    if (!uk_utils_write_binary_file(file_name, uk_utils_byte_stream_get_data(stream), uk_utils_byte_stream_get_size(stream))) {
        uk_utils_stacktrace_push_msg("Failed to write binary file with cipher data");
        goto clean_up;
    }

    result = true;

clean_up:
    uk_crypto_sym_encrypter_destroy_all(sym_encrypter);
    uk_utils_byte_stream_destroy(stream);
    uk_utils_safe_free(iv);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(file_name);
    return result;
}

static bool crypto_metadata_write_asym(const char *folder_name, const char *uid,
    const char *password, uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key, const char *keystore_type) {

    bool result;
    uk_crypto_pkcs12_keystore *keystore;
    unsigned char *friendly_name;
    size_t friendly_name_size;
    const char *file_name, *string_friendly_name;

    if (!certificate || !private_key) {
        uk_utils_logger_trace("No certificate or private key to write for '%s'", keystore_type);
        return true;
    }

    uk_utils_check_parameter_or_return(keystore_type);

    result = false;
    keystore = NULL;
    friendly_name = NULL;
    file_name = NULL;
    string_friendly_name = NULL;

    if ((friendly_name = uk_crypto_friendly_name_build((unsigned char *)uid, strlen(uid), keystore_type, &friendly_name_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build friendly name for '%s'", keystore_type);
        goto clean_up;
    }

    if ((string_friendly_name = uk_utils_string_create_from_bytes(friendly_name, friendly_name_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert friendly name from bytes to string");
        goto clean_up;
    }

    if ((keystore = uk_crypto_pkcs12_keystore_create(certificate, private_key, string_friendly_name)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create pkcs12 keystore with friendly name '%s'", string_friendly_name);
        goto clean_up;
    }

    if ((file_name = uk_utils_strcat_variadic("sssss", folder_name, "/", uid, "_asym_", keystore_type)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name with name '%s' for keystore '%s'", uid, keystore_type);
        goto clean_up;
    }

    if (!uk_crypto_pkcs12_keystore_write(keystore, file_name, password)) {
        uk_utils_stacktrace_push_msg("Failed to write keystore '%s'", file_name);
        goto clean_up;
    }

    result = true;

clean_up:
    uk_crypto_pkcs12_keystore_destroy(keystore);
    uk_utils_safe_free(friendly_name);
    uk_utils_safe_free(file_name);
    uk_utils_safe_free(string_friendly_name);
    return result;
}

static bool crypto_metadata_read_sym(uk_crypto_crypto_metadata *metadata, const char *folder_name, const char *uid,
    const char *password) {

    bool result;
    const char *file_name;
    uk_utils_byte_stream *raw_data_stream, *iv_stream, *cipher_data_stream, *plain_data_stream;
    unsigned char *raw_data, *plain_data, *sym_key_data;
    size_t raw_data_size, plain_data_size;
    uk_crypto_sym_encrypter *sym_encrypter;
    int sym_key_size, digest_name_size, cipher_name_size;
    const char *digest_name, *cipher_name;

    result = false;
    file_name = NULL;
    raw_data_stream = uk_utils_byte_stream_create();
    iv_stream = uk_utils_byte_stream_create();
    cipher_data_stream = uk_utils_byte_stream_create();
    plain_data_stream = uk_utils_byte_stream_create();
    raw_data = NULL;
    plain_data = NULL;
    sym_encrypter = NULL;
    sym_key_data = NULL;
    digest_name = NULL;
    cipher_name = NULL;

    if ((file_name = uk_utils_strcat_variadic("ssss", folder_name, "/", uid, "_sym")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name for sym crypto metadata");
        goto clean_up;
    }

    if (!uk_utils_is_file_exists(file_name)) {
        uk_utils_logger_trace("File '%s' doesn't exists", file_name);
        return true;
    } else {
        uk_utils_logger_trace("File '%s' exists", file_name);
    }

    if ((raw_data = uk_utils_read_binary_file(file_name, &raw_data_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to read binary file '%s'", file_name);
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(raw_data_stream, raw_data, raw_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to copy raw data to byte stream");
        goto clean_up;
    }
    uk_utils_byte_stream_set_position(raw_data_stream, 0);

    if (!uk_utils_byte_read_next_stream(raw_data_stream, iv_stream)) {
        uk_utils_stacktrace_push_msg("Failed to read and copy IV to stream");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_stream(raw_data_stream, cipher_data_stream)) {
        uk_utils_stacktrace_push_msg("Failed to read and copy cipher data to stream");
        goto clean_up;
    }

    if ((sym_encrypter = uk_crypto_sym_encrypter_default_create(uk_crypto_sym_key_create_from_string(password))) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create default sym encrypter");
        goto clean_up;
    }

    if (!uk_crypto_sym_encrypter_decrypt(sym_encrypter, uk_utils_byte_stream_get_data(cipher_data_stream), uk_utils_byte_stream_get_size(cipher_data_stream),
        uk_utils_byte_stream_get_data(iv_stream), &plain_data, &plain_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to decrypt cipher data");
        goto clean_up;
    }

    if (!uk_utils_byte_writer_append_bytes(plain_data_stream, plain_data, plain_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to copy plain data to stream");
        goto clean_up;
    }
    uk_utils_byte_stream_set_position(plain_data_stream, 0);

    if (!uk_utils_byte_read_next_int(plain_data_stream, &sym_key_size)) {
        uk_utils_stacktrace_push_msg("Failed to read sym key size");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_int(plain_data_stream, &digest_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to read digest name size");
        goto clean_up;
    }
    if (!uk_utils_byte_read_next_int(plain_data_stream, &cipher_name_size)) {
        uk_utils_stacktrace_push_msg("Failed to read cipher name size");
        goto clean_up;
    }

    if (sym_key_size > 0) {
        if (!uk_utils_byte_read_next_bytes(plain_data_stream, &sym_key_data, sym_key_size)) {
            uk_utils_stacktrace_push_msg("Failed to read sym key data from plain data stream");
            goto clean_up;
        }
        if (!uk_crypto_crypto_metadata_set_sym_key(metadata, uk_crypto_sym_key_create(sym_key_data, (size_t)sym_key_size))) {
            uk_utils_safe_free(sym_key_data);
            uk_utils_stacktrace_push_msg("Failed to set sym key to crypto metadata");
            goto clean_up;
        }
    }

    if (digest_name_size > 0) {
        if (!uk_utils_byte_read_next_string(plain_data_stream, &digest_name, (size_t)digest_name_size)) {
            uk_utils_stacktrace_push_msg("Failed to read digest name from plain data stream");
            goto clean_up;
        }
        if (!uk_crypto_crypto_metadata_set_digest_name(metadata, digest_name)) {
            uk_utils_safe_free(sym_key_data);
            uk_utils_safe_free(digest_name);
            uk_utils_stacktrace_push_msg("Failed to set digest name to crypto metadata");
            goto clean_up;
        }
    }

    if (cipher_name_size > 0) {
        if (!uk_utils_byte_read_next_string(plain_data_stream, &cipher_name, (size_t)cipher_name_size)) {
            uk_utils_stacktrace_push_msg("Failed to read cipher name from plain data stream");
            goto clean_up;
        }
        if (!uk_crypto_crypto_metadata_set_cipher_name(metadata, cipher_name)) {
            uk_utils_safe_free(sym_key_data);
            uk_utils_safe_free(digest_name);
            uk_utils_safe_free(cipher_name);
            uk_utils_stacktrace_push_msg("Failed to set cipher name to crypto metadata");
            goto clean_up;
        }
    }

    result = true;

clean_up:
    uk_utils_safe_free(file_name);
    uk_utils_byte_stream_destroy(raw_data_stream);
    uk_utils_byte_stream_destroy(iv_stream);
    uk_utils_byte_stream_destroy(cipher_data_stream);
    uk_utils_byte_stream_destroy(plain_data_stream);
    uk_utils_safe_free(raw_data);
    uk_utils_safe_free(plain_data);
    uk_crypto_sym_encrypter_destroy_all(sym_encrypter);
    return result;
}

static bool crypto_metadata_read_asym(const char *folder_name, const char *uid,
    const char *password, const char *keystore_type, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key,
    uk_crypto_public_key **public_key) {

    bool result;
    unsigned char *friendly_name;
    const char *file_name, *string_friendly_name;
    size_t friendly_name_size;
    uk_crypto_pkcs12_keystore *keystore;

    uk_utils_check_parameter_or_return(keystore_type);

    result = false;
    friendly_name = NULL;
    file_name = NULL;
    string_friendly_name = NULL;
    keystore = NULL;

    if ((file_name = uk_utils_strcat_variadic("sssss", folder_name, "/", uid, "_asym_", keystore_type)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build file name with name '%s' for keystore '%s'", uid, keystore_type);
        goto clean_up;
    }

    if (!uk_utils_is_file_exists(file_name)) {
        uk_utils_logger_trace("File '%s' doesn't exists", file_name);
        return true;
    } else {
        uk_utils_logger_trace("File '%s' exists", file_name);
    }

    if ((friendly_name = uk_crypto_friendly_name_build((unsigned char *)uid, strlen(uid), keystore_type, &friendly_name_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to build friendly name for '%s'", keystore_type);
        goto clean_up;
    }

    if ((string_friendly_name = uk_utils_string_create_from_bytes(friendly_name, friendly_name_size)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to convert friendly name from bytes to string");
        goto clean_up;
    }

    if ((keystore = uk_crypto_pkcs12_keystore_load(file_name, password)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to load pkcs12 keystore '%s'", file_name);
        goto clean_up;
    }

    if ((*certificate = keystore->certificate) == NULL) {
        uk_utils_stacktrace_push_msg("Keystore is read but there is no certificate");
        goto clean_up;
    }
    if ((*private_key = keystore->private_key) == NULL) {
        uk_utils_stacktrace_push_msg("Keystore is read but there is no private key");
        goto clean_up;
    }

    if ((*public_key = uk_crypto_rsa_public_key_from_x509_certificate(*certificate)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract RSA public key from specified certificate");
        uk_crypto_x509_certificate_destroy(*certificate);
        uk_crypto_private_key_destroy(*private_key);
        goto clean_up;
    }

    result = true;

clean_up:
    uk_utils_safe_free(friendly_name);
    uk_utils_safe_free(file_name);
    uk_utils_safe_free(string_friendly_name);
    uk_crypto_pkcs12_keystore_destroy(keystore);
    return result;
}
