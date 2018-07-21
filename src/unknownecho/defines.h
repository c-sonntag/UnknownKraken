/*******************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                        *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
 *                                                                             *
 *   LibUnknownEcho is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by      *
 *   the Free Software Foundation, either version 3 of the License, or         *
 *   (at your option) any later version.                                       *
 *                                                                             *
 *   LibUnknownEcho is distributed in the hope that it will be useful,         *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of            *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             *
 *   GNU General Public License for more details.                              *
 *                                                                             *
 *   You should have received a copy of the GNU General Public License         *
 *   along with LibUnknownEcho.  If not, see <http://www.gnu.org/licenses/>.   *
 *******************************************************************************/

/**
 *  @file      defines.h
 *  @brief     Global defines of LibUnknownEcho.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#include <unknownecho/network/api/communication/communication_type.h>

#ifndef UNKNOWNECHO_DEFINES_H
#define UNKNOWNECHO_DEFINES_H

/* Lib defines */

#define UNKNOWNECHO_LIB_NAME                         "LibUnknownEcho"
#define UNKNOWNECHO_LiB_VERSION                      "0.1"

/* Crypto defines */

#define UNKNOWNECHO_DEFAULT_CIPHER_NAME              "aes-256-cbc"
#define UNKNOWNECHO_DEFAULT_DIGEST_NAME              "sha256"

/* X509 generation defines */

#define UNKNOWNECHO_DEFAULT_X509_NOT_AFTER_YEAR      1
#define UNKNOWNECHO_DEFAULT_X509_NOT_AFTER_DAYS      365
#define UNKNOWNECHO_DEFAULT_RSA_KEY_BITS             2048
#define UNKNOWNECHO_DEFUALT_X509_SERIAL_LENGTH       20

/* Channel protocol defines */

#define UNKNOWNECHO_DEFAULT_SERVER_PERSISTENT_PATH   "out/server"
#define UNKNOWNECHO_DEFAULT_CLIENT_PERSISTENT_PATH   "out"
#define UNKNOWNECHO_DEFAULT_SERVER_CERTIFICATES_PATH "out/certificate"
#define UNKNOWNECHO_LOCALHOST                        "127.0.0.1"
#define UNKNOWNECHO_DEFAULT_CSR_SERVER_PORT          5002
#define UNKNOWNECHO_DEFAULT_CSL_SERVER_PORT          5001
#define UNKNOWNECHO_DEFAULT_CLIENT_CHANNELS_NUMBER   3

/* Colors use in logger */

#if defined(__unix__)

#define UNKNOWNECHO_SKY_BLUE_COLOR                   "\x1b[94m"
#define UNKNOWNECHO_TURQUOISE_BLUE_COLOR             "\x1b[36m"
#define UNKNOWNECHO_GREEN_COLOR                      "\x1b[32m"
#define UNKNOWNECHO_YELLOW_COLOR                     "\x1b[33m"
#define UNKNOWNECHO_RED_COLOR                        "\x1b[31m"
#define UNKNOWNECHO_PURPLE_COLOR                     "\x1b[35m"
#define UNKNOWNECHO_GRAY_COLOR                       "\x1b[90m"
#define UNKNOWNECHO_WHITE_COLOR                      "\x1b[0m"

/* @todo replace by detecting the terminal type as some Windows user has bash like terminal */
#elif defined(_WIN32) || defined(_WIN64)

#define UNKNOWNECHO_SKY_BLUE_COLOR                   ""
#define UNKNOWNECHO_TURQUOISE_BLUE_COLOR             ""
#define UNKNOWNECHO_GREEN_COLOR                      ""
#define UNKNOWNECHO_YELLOW_COLOR                     ""
#define UNKNOWNECHO_RED_COLOR                        ""
#define UNKNOWNECHO_PURPLE_COLOR                     ""
#define UNKNOWNECHO_GRAY_COLOR                       ""
#define UNKNOWNECHO_WHITE_COLOR                      ""

#endif

/* Optional defines */

#define UNKNOWNECHO_BOOL

/* Communication */

/* By default, network communications use SOCKET */
#define UNKNOWNECHO_DEFAULT_COMMUNICATION_TYPE       UNKNOWNECHO_COMMUNICATION_SOCKET
#define UNKNOWNECHO_COMMUNICATION_SOCKET             "SOCKET"

#define UNKNOWNECHO_DEFAULT_COMMUNICATION_TYPE_ID    UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET

#endif
