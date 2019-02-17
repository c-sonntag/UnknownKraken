/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
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
 *  @file      logger_manager.h
 *  @brief     Logger manager return the current (thread-local) logger.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @see       logger.h
 *  @see       logger_struct.h
 */

#ifndef UnknownKrakenUtils_LOGGER_MANAGER_H
#define UnknownKrakenUtils_LOGGER_MANAGER_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/logger/logger_struct.h>
#include <uk/utils/logger/logger.h>

bool uk_utils_logger_manager_init();

void uk_utils_logger_manager_uninit();

uk_utils_logger *uk_utils_logger_manager_get_logger();

#endif
