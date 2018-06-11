#ifndef UNKNOWNECHO_COMMUNICATION_METADATA_FACTORY_H
#define UNKNOWNECHO_COMMUNICATION_METADATA_FACTORY_H

#include <unknownecho/network/api/communication/communication_metadata.h>

ue_communication_metadata *ue_communication_metadata_create_socket_type(const char *uid, const char *host, int port);

#endif
