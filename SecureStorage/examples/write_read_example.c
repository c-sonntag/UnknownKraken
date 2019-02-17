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

#include <uk/sstorage/sstorage.h>
#include <uk/sstorage/writer.h>
#include <uk/sstorage/reader.h>
#include <uk/sstorage/entry.h>
#include <uk/crypto/uecm.h>
#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stdlib.h>
#include <stdio.h>

#define STORAGE_FILE_NAME "storage_example.sst"
#define DATA_TYPE_EXAMPLE 12
#define DATA_EXAMPLE "Hello world !"

static bool write_storage(const char *file_name, uk_crypto_crypto_metadata *crypto_metadata) {
    bool result;
    sstorage *storage;
    uk_sstorage_entry *entry;

    result = false;
    storage = NULL;
    entry = NULL;

    if ((storage = uk_sstorage_open_write(file_name, crypto_metadata)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed open new storage in write mode");
        return false;
    }

    if ((entry = uk_sstorage_entry_create(DATA_TYPE_EXAMPLE)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create new entry with DATA_TYPE_EXAMPLE");
        goto clean_up;
    }

    if (!uk_sstorage_entry_add_string(entry, DATA_EXAMPLE)) {
        uk_utils_stacktrace_push_msg("Failed to add new string DATA_EXAMPLE to entry");
        goto clean_up;
    }

    if (!uk_sstorage_push_entry(storage, entry)) {
        uk_utils_stacktrace_push_msg("Failed to push new entry to storage");
        goto clean_up;
    }

    result = true;

clean_up:
    if (entry) {
        uk_sstorage_entry_destroy(entry);
    }
    if (storage) {
        uk_sstorage_close(storage);
    }
    return result;
}

static bool read_storage(const char *file_name, uk_crypto_crypto_metadata *crypto_metadata) {
    bool result;
    sstorage *storage;
    uk_sstorage_entry *entry;

    result = false;
    storage = NULL;
    entry = NULL;

    if ((storage = uk_sstorage_open_read(file_name, crypto_metadata)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to open new storage in read mode");
        return false;
    }

    if (!uk_sstorage_has_next(storage)) {
        uk_utils_stacktrace_push_msg("has_next() returned false, but it shouldn't");
        goto clean_up;
    }

    if ((entry = uk_sstorage_next(storage)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to read next entry");
        goto clean_up;
    }

    /* Dump the plain data of the entry */
    uk_utils_byte_stream_print_string(uk_sstorage_entry_get_data(entry), stdout);

    result = true;

clean_up:
    if (entry) {
        uk_sstorage_entry_destroy(entry);
    }
    if (storage) {
        uk_sstorage_close(storage);
    }
    return result;
}

int main() {
    uk_crypto_crypto_metadata *crypto_metadata;

    if (!uk_utils_init()) {
        fprintf(stderr, "[ERROR] Failed to init LibErrorInterceptor");
        exit(EXIT_FAILURE);
    }

    if (!uk_crypto_init()) {
        fprintf(stderr, "[ERROR] Failed to init LibUnknownEchoCryptoModule");
        exit(EXIT_FAILURE);
    }

    crypto_metadata = NULL;

    uk_utils_logger_info("Generating crypto metadata...");
    if ((crypto_metadata = uk_crypto_crypto_metadata_create_default()) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create random crypto metadata");
        goto clean_up;
    }
    uk_utils_logger_info("Crypto metadata generated.");

    uk_utils_logger_info("Writing new storage...");
    if (!write_storage(STORAGE_FILE_NAME, crypto_metadata)) {
        uk_utils_stacktrace_push_msg("Failed to write example storage");
        goto clean_up;
    }
    uk_utils_logger_info("New storage wrote.");

    uk_utils_logger_info("Reading new storage...");
    if (!read_storage(STORAGE_FILE_NAME, crypto_metadata)) {
        uk_utils_stacktrace_push_msg("Failed to read example storage");
        goto clean_up;
    }
    uk_utils_logger_info("New storage read.");

    uk_utils_logger_info("Done.");

clean_up:
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_stacktrace("Stacktrace is filled with following error(s):");
        uk_utils_stacktrace_print();
    }
    uk_crypto_crypto_metadata_destroy(crypto_metadata);
    uk_crypto_uninit();
    uk_utils_uninit();
    return EXIT_SUCCESS;
}
