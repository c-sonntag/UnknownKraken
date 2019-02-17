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

/**
 *  @file      x509_certificate_generation.h
 *  @brief     Generate X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       x509_certificate.h
 *  @see       x509_certificate_parameters.h
 *  @todo      add callback for RSA generation
 */

#ifndef UnknownKrakenCrypto_X509_CERTFICATE_GENERATION_H
#define UnknownKrakenCrypto_X509_CERTFICATE_GENERATION_H

#include <uk/utils/ueum.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/certificate/x509_certificate_parameters.h>
#include <uk/crypto/api/key/private_key.h>

#include <stddef.h>

bool uk_crypto_x509_certificate_generate(uk_crypto_x509_certificate_parameters *parameters, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key);

bool uk_crypto_x509_certificate_print_pair(uk_crypto_x509_certificate *certificate, uk_crypto_private_key *private_key,
    char *certificate_file_name, char *private_key_file_name, char *passphrase);

#endif
