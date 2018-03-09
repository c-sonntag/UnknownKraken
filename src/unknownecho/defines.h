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
 *  @file      defines.h
 *  @brief     Global defines of LibUnknownEcho.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

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
#define UNKNOWNECHO_DEFAULT_RSA_KEY_BITS             4096
#define UNKNOWNECHO_DEFUALT_X509_SERIAL_LENGTH       20

/* Channel protocol defines */

#define UNKNOWNECHO_DEFAULT_SERVER_PERSISTENT_PATH   "out/server"
#define UNKNOWNECHO_DEFAULT_CLIENT_PERSISTENT_PATH   "out"
#define UNKNOWNECHO_DEFAULT_SERVER_CERTIFICATES_PATH "out/certificate"
#define UNKNOWNECHO_LOCALHOST                        "127.0.0.1"
#define UNKNOWNECHO_DEFAULT_CSR_SERVER_PORT          5002
#define UNKNOWNECHO_DEFAULT_TLS_SERVER_PORT          5001
#define UNKNOWNECHO_DEFAULT_CLIENT_CHANNELS_NUMBER   3

#endif
