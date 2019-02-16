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
 *  @file      sym_key_factory.h
 *  @brief     Factory to create Symmetric Key (random or from file).
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_KEY_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_KEY_FACTORY_H

#include <uecm/api/key/sym_key.h>

uecm_sym_key *uecm_sym_key_create_random();

uecm_sym_key *uecm_sym_key_create_from_file(char *file_path);

uecm_sym_key *uecm_sym_key_create_from_string(const char *string);

#endif
