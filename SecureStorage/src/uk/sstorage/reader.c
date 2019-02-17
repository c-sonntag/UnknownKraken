/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibSecureStorage.                                      *
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

#include <uk/sstorage/reader.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ei.h>

#include <stdio.h>
#include <stddef.h>

bool uk_sstorage_has_next(sstorage *storage) {
    unsigned char *header;

    uk_utils_check_parameter_or_return(storage);

    if (storage->mode != SSTORAGE_READ) {
        uk_utils_stacktrace_push_msg("File mode isn't read");
        return false;
    }

    if (feof(storage->fd)) {
        uk_utils_logger_debug("End of file reached");
        return false;
    }

	header = NULL;

    uk_utils_safe_alloc(header, unsigned char, 4);

    /* Get the data type */
    if (fread(header, 4, 1, storage->fd) != 1) {
        uk_utils_stacktrace_push_errno();
        uk_utils_safe_free(header);
        return false;
    }

    if (feof(storage->fd)) {
        uk_utils_logger_debug("End of file reached");
        uk_utils_safe_free(header);
        return false;
    }

    /* Back to previous position */
    fseek(storage->fd, -4L, SEEK_CUR);

    uk_utils_safe_free(header);

    return true;
}

uk_sstorage_entry *uk_sstorage_next(sstorage *storage) {
    uk_sstorage_entry *entry;
    int data_type, cipher_data_size;
    unsigned char *cipher_data, *plain_data, *header;
    size_t plain_data_size;

    uk_utils_check_parameter_or_return(storage);

    entry = NULL;
    cipher_data = NULL;
    plain_data = NULL;
    header = NULL;

    if (storage->mode != SSTORAGE_READ) {
        uk_utils_stacktrace_push_msg("File mode isn't read");
        return NULL;
    }

    if (feof(storage->fd)) {
        uk_utils_stacktrace_push_msg("End of file reached");
        return NULL;
    }

    uk_utils_safe_alloc(header, unsigned char, 4);

    /* Get the data type */
    if (fread(header, 4, 1, storage->fd) != 1) {
        uk_utils_stacktrace_push_errno();
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    if (!uk_utils_bytes_to_int(header, &data_type)) {
        uk_utils_stacktrace_push_msg("Failed to convert data type to int");
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    /* Get the cipher data size */
    if (fread(header, 4, 1, storage->fd) != 1) {
        uk_utils_stacktrace_push_errno();
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    if (!uk_utils_bytes_to_int(header, &cipher_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to convert cipher data size to int");
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    uk_utils_safe_alloc(cipher_data, unsigned char, cipher_data_size);

    if (fread(cipher_data, (size_t)cipher_data_size, 1, storage->fd) == 0) {
        uk_utils_stacktrace_push_errno();
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    if (!uk_crypto_decipher_cipher_data_default(cipher_data, (size_t)cipher_data_size,
        uk_crypto_crypto_metadata_get_cipher_private_key(storage->crypto_metadata),
        &plain_data, &plain_data_size)) {

        uk_utils_stacktrace_push_msg("Failed to decipher cipher data with default parameters");
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    if ((entry = uk_sstorage_entry_create(data_type)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new storage entry");
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

    if (!uk_sstorage_entry_add_bytes(entry, plain_data, plain_data_size)) {
        uk_utils_stacktrace_push_msg("Failed to add bytes to new storage entry");
        uk_sstorage_entry_destroy(entry);
        goto clean_up;
    }

clean_up:
    uk_utils_safe_free(header);
    uk_utils_safe_free(cipher_data);
    uk_utils_safe_free(plain_data);
    return entry;
}
