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
 *  @file      defines.h
 *  @brief     Global defines of LibUnknownEcho.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_DEFINES_H
#define UnknownKrakenCrypto_DEFINES_H

/* Crypto defines */

#define UnknownKrakenCrypto_DEFAULT_CIPHER_NAME              "aes-256-cbc"
#define UnknownKrakenCrypto_DEFAULT_DIGEST_NAME              "sha256"

/* X509 generation defines */

#define UnknownKrakenCrypto_DEFAULT_X509_NOT_AFTER_YEAR      1
#define UnknownKrakenCrypto_DEFAULT_X509_NOT_AFTER_DAYS      365
#define UnknownKrakenCrypto_DEFAULT_RSA_KEY_BITS             4096
#define UnknownKrakenCrypto_DEFUALT_X509_SERIAL_LENGTH       20

#endif
