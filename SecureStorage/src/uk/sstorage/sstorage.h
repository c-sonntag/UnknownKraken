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

#ifndef UnknownKrakenSecureStorage_SSTORAGE_H
#define UnknownKrakenSecureStorage_SSTORAGE_H

#include <uk/crypto/uecm.h>

#include <stdio.h>

typedef enum {
    SSTORAGE_READ,
    SSTORAGE_WRITE
} uk_sstorage_mode;

typedef struct {
    const char *file_name;
    uk_crypto_crypto_metadata *crypto_metadata;
    FILE *fd;
    uk_sstorage_mode mode;
} sstorage;

sstorage *uk_sstorage_open_read(const char *file_name, uk_crypto_crypto_metadata *crypto_metadata);

sstorage *uk_sstorage_open_write(const char *file_name, uk_crypto_crypto_metadata *crypto_metadata);

void uk_sstorage_close(sstorage *storage);

bool ssorage_delete(sstorage *storage);

#endif
