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

#include <uk/unknownecho/network/factory/communication_metadata_factory.h>
#include <uk/unknownecho/defines.h>

uk_ue_communication_metadata *uk_ue_communication_metadata_create_socket_type(const char *uid, const char *host, int port) {
    uk_ue_communication_metadata *metadata;

    metadata = uk_ue_communication_metadata_create_empty();
    uk_ue_communication_metadata_set_uid(metadata, uid);
    uk_ue_communication_metadata_set_type(metadata, UnknownKrakenUnknownEcho_COMMUNICATION_TYPE_SOCKET);
    uk_ue_communication_metadata_set_host(metadata, host);
    uk_ue_communication_metadata_set_port(metadata, port);
    uk_ue_communication_metadata_set_destination_type(metadata, UnknownKrakenUnknownEcho_RELAY_SERVER);

    return metadata;
}
