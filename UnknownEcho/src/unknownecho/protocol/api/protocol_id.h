/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEcho.                                        *
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

#ifndef UNKNOWNECHO_PROTOCOL_ID_H
#define UNKNOWNECHO_PROTOCOL_ID_H

#include <ueum/ueum.h>

typedef enum {
    UNKNOWNECHO_PROTOCOL_ID_CHANNEL = 0,
    UNKNOWNECHO_PROTOCOL_ID_RELAY
} ue_protocol_id;

bool ue_protocol_id_is_valid(int id);

#endif