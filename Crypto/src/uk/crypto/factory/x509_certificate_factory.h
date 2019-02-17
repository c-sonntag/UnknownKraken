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
 *  @file      x509_certificate_factory.h
 *  @brief     Factory to create signed or self-signed X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @todo      Add callback for RSA keypair gen
 */

#ifndef UnknownKrakenCrypto_X509_CERTIFICATE_FACTORY_H
#define UnknownKrakenCrypto_X509_CERTIFICATE_FACTORY_H

#include <uk/utils/ueum.h>
#include <uk/crypto/api/certificate/x509_certificate.h>
#include <uk/crypto/api/key/private_key.h>

bool uk_crypto_x509_certificate_generate_self_signed_ca(char *CN, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key);

bool uk_crypto_x509_certificate_generate_signed(uk_crypto_x509_certificate *ca_certificate, uk_crypto_private_key *ca_private_key,
    char *CN, uk_crypto_x509_certificate **certificate, uk_crypto_private_key **private_key);

#endif
