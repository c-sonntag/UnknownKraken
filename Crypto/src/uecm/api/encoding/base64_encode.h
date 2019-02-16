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
 *  @file      base64_encode.h
 *  @brief     Encode byte data with Base64 algorithm.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_BASE64_ENCODE_H
#define UNKNOWNECHOCRYPTOMODULE_BASE64_ENCODE_H

#include <stddef.h>

unsigned char *uecm_base64_encode(const unsigned char *src, size_t len, size_t *out_len);

#endif
