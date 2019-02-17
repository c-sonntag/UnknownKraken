/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#ifndef UnknownKrakenUtils_INPUT_H
#define UnknownKrakenUtils_INPUT_H

#include <uk/utils/compiler/ssize_t.h>

typedef enum {
    UnknownKrakenUtils_STDIN_INPUT,
    UnknownKrakenUtils_PUSH_INPUT
} uk_utils_user_input_mode;

char *uk_utils_input_string(char *prefix);

char *uk_utils_input_password(const char *prompt_message, ssize_t max_size);

#endif
