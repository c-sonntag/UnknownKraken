/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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
 *  @copyright GNU Public License.
 */

#include <uk/unknownecho/network/api/communication/communication_type.h>

#ifndef UnknownKrakenUnknownEcho_DEFINES_H
#define UnknownKrakenUnknownEcho_DEFINES_H

/* Lib defines */

#define UnknownKrakenUnknownEcho_LIB_NAME                         "LibUnknownEcho"
#define UnknownKrakenUnknownEcho_LiB_VERSION                      "0.1"

/* Crypto defines */

#define UnknownKrakenUnknownEcho_DEFAULT_CIPHER_NAME              "aes-256-cbc"
#define UnknownKrakenUnknownEcho_DEFAULT_DIGEST_NAME              "sha256"

/* X509 generation defines */

#define UnknownKrakenUnknownEcho_DEFAULT_X509_NOT_AFTER_YEAR      1
#define UnknownKrakenUnknownEcho_DEFAULT_X509_NOT_AFTER_DAYS      365
#define UnknownKrakenUnknownEcho_DEFAULT_RSA_KEY_BITS             2048
#define UnknownKrakenUnknownEcho_DEFUALT_X509_SERIAL_LENGTH       20

/* Channel protocol defines */

#define UnknownKrakenUnknownEcho_DEFAULT_SERVER_PERSISTENT_PATH   "out/server"
#define UnknownKrakenUnknownEcho_DEFAULT_CLIENT_PERSISTENT_PATH   "out"
#define UnknownKrakenUnknownEcho_DEFAULT_SERVER_CERTIFICATES_PATH "out/certificate"
#define UnknownKrakenUnknownEcho_LOCALHOST                        "127.0.0.1"
#define UnknownKrakenUnknownEcho_DEFAULT_CSR_SERVER_PORT          5002
#define UnknownKrakenUnknownEcho_DEFAULT_CSL_SERVER_PORT          5001
#define UnknownKrakenUnknownEcho_DEFAULT_CLIENT_CHANNELS_NUMBER   3

/* Colors use in logger */

#if defined(__unix__)

#define UnknownKrakenUnknownEcho_SKY_BLUE_COLOR                   "\x1b[94m"
#define UnknownKrakenUnknownEcho_TURQUOISE_BLUE_COLOR             "\x1b[36m"
#define UnknownKrakenUnknownEcho_GREEN_COLOR                      "\x1b[32m"
#define UnknownKrakenUnknownEcho_YELLOW_COLOR                     "\x1b[33m"
#define UnknownKrakenUnknownEcho_RED_COLOR                        "\x1b[31m"
#define UnknownKrakenUnknownEcho_PURPLE_COLOR                     "\x1b[35m"
#define UnknownKrakenUnknownEcho_GRAY_COLOR                       "\x1b[90m"
#define UnknownKrakenUnknownEcho_WHITE_COLOR                      "\x1b[0m"

/* @todo replace by detecting the terminal type as some Windows user has bash like terminal */
#elif defined(_WIN32) || defined(_WIN64)

#define UnknownKrakenUnknownEcho_SKY_BLUE_COLOR                   ""
#define UnknownKrakenUnknownEcho_TURQUOISE_BLUE_COLOR             ""
#define UnknownKrakenUnknownEcho_GREEN_COLOR                      ""
#define UnknownKrakenUnknownEcho_YELLOW_COLOR                     ""
#define UnknownKrakenUnknownEcho_RED_COLOR                        ""
#define UnknownKrakenUnknownEcho_PURPLE_COLOR                     ""
#define UnknownKrakenUnknownEcho_GRAY_COLOR                       ""
#define UnknownKrakenUnknownEcho_WHITE_COLOR                      ""

#endif

/* Optional defines */

#define UnknownKrakenUnknownEcho_BOOL

/* Communication */

/* By default, network communications use SOCKET */
#define UnknownKrakenUnknownEcho_DEFAULT_COMMUNICATION_TYPE       UnknownKrakenUnknownEcho_COMMUNICATION_SOCKET
#define UnknownKrakenUnknownEcho_COMMUNICATION_SOCKET             "SOCKET"

#define UnknownKrakenUnknownEcho_DEFAULT_COMMUNICATION_TYPE_ID    UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET

#endif
