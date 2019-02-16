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
 *  @file      pkcs12_keystore_factory.h
 *  @brief     Factory to create PKCS12 keystore from scratch or from file.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_FACTORY_H

#include <uecm/api/keystore/pkcs12_keystore.h>

uecm_pkcs12_keystore *uecm_pkcs12_keystore_create_random(char *CN, char *friendly_name);

uecm_pkcs12_keystore *uecm_pkcs12_keystore_create_from_files(char *certificate_path, char *private_key_path, const char *private_key_password, char *friendly_name);

#endif
