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
 *  @file      sym_key.h
 *  @brief     Symmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_KEY_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_KEY_H

#include <ueum/ueum.h>

#include <stddef.h>

typedef struct {
    unsigned char *data;
    size_t size;
} uecm_sym_key;

uecm_sym_key *uecm_sym_key_create(unsigned char *data, size_t size);

void uecm_sym_key_destroy(uecm_sym_key *key);

size_t uecm_sym_key_get_min_size();

bool uecm_sym_key_is_valid(uecm_sym_key *key);

#endif
