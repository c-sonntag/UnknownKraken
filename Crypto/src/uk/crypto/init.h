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
 *  @file      init.h
 *  @brief     Init and uninit functions for the global context of LibUnknownEchoCryptoModule.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenCrypto_INIT_H
#define UnknownKrakenCrypto_INIT_H

#include <stdio.h>
#include <stdlib.h>

int uk_crypto_init();

#define uk_crypto_init_or_die() \
    if (!uk_crypto_init()) { \
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEchoCryptoModule"); \
        exit(EXIT_FAILURE); \
    } \

void uk_crypto_uninit();

#endif
