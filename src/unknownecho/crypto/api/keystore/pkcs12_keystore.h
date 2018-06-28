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

/**
 *  @file      pkcs12_keystore.h
 *  @brief     PKCS12 keystore structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @details   - Little description : https://en.wikipedia.org/wiki/PKCS_12
 *             - RFC : https://tools.ietf.org/html/rfc7292
 */

#ifndef UNKNOWNECHO_PKCS12_KEYSTORE_H
#define UNKNOWNECHO_PKCS12_KEYSTORE_H

#include <unknownecho/crypto/api/certificate/x509_certificate.h>
#include <unknownecho/crypto/api/key/private_key.h>
#include <unknownecho/bool.h>

typedef struct {
    ue_x509_certificate *certificate;
    ue_private_key *private_key;
    ue_x509_certificate **other_certificates;
    int other_certificates_number;
    char *friendly_name;
} ue_pkcs12_keystore;

ue_pkcs12_keystore *ue_pkcs12_keystore_create(ue_x509_certificate *certificate, ue_private_key *private_key, const char *friendly_name);

ue_pkcs12_keystore *ue_pkcs12_keystore_load(const char *file_name, const char *passphrase);

void ue_pkcs12_keystore_destroy(ue_pkcs12_keystore *keystore);

void ue_pkcs12_keystore_destroy_all(ue_pkcs12_keystore *keystore);

bool ue_pkcs12_keystore_add_certificate(ue_pkcs12_keystore *keystore, ue_x509_certificate *certificate, const unsigned char *friendly_name, size_t friendly_name_size);

bool ue_pkcs12_keystore_add_certificate_from_file(ue_pkcs12_keystore *keystore, const char *file_name, const unsigned char *friendly_name, size_t friendly_name_size);

bool ue_pkcs12_keystore_add_certificate_from_bytes(ue_pkcs12_keystore *keystore, unsigned char *data, size_t data_size, const unsigned char *friendly_name,
    size_t friendly_name_size);

bool ue_pkcs12_keystore_add_certificates_bundle(ue_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

bool ue_pkcs12_keystore_remove_certificate(ue_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

ue_x509_certificate *ue_pkcs12_keystore_find_certificate_by_friendly_name(ue_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

bool ue_pkcs12_keystore_write(ue_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

#endif
