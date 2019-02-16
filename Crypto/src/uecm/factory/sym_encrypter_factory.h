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
 *  @file      sym_encrypter_factory.h
 *  @brief     Factory to create Symmetric Encrypter from Symmetric Key (default is AES-CBC-256).
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_FACTORY_H

#include <uecm/api/encryption/sym_encrypter.h>
#include <uecm/api/key/sym_key.h>

uecm_sym_encrypter *uecm_sym_encrypter_aes_cbc_create(uecm_sym_key *key);

uecm_sym_encrypter *uecm_sym_encrypter_rc4_create(uecm_sym_key *key);

uecm_sym_encrypter *uecm_sym_encrypter_default_create(uecm_sym_key *key);

#endif
