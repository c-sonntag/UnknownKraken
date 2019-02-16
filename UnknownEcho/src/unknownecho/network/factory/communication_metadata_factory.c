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

#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/defines.h>

ue_communication_metadata *ue_communication_metadata_create_socket_type(const char *uid, const char *host, int port) {
    ue_communication_metadata *metadata;

    metadata = ue_communication_metadata_create_empty();
    ue_communication_metadata_set_uid(metadata, uid);
    ue_communication_metadata_set_type(metadata, UNKNOWNECHO_COMMUNICATION_TYPE_SOCKET);
    ue_communication_metadata_set_host(metadata, host);
    ue_communication_metadata_set_port(metadata, port);
    ue_communication_metadata_set_destination_type(metadata, UNKNOWNECHO_RELAY_SERVER);

    return metadata;
}
