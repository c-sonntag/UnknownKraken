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

#ifndef UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_STATE_H
#define UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_STATE_H

typedef enum {
    UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_FREE_STATE,
    UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_READ_STATE,
    UnknownKrakenUnknownEcho_COMMUNICATION_CONNECTION_WRITE_STATE
} uk_ue_communication_connection_state;

#endif