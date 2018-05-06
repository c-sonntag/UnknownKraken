#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/defines.h>

ue_communication_metadata *ue_communication_metadata_create_socket_type(const char *host, int port) {
    ue_communication_metadata *metadata;

    metadata = ue_communication_metadata_create_empty();
    ue_communication_metadata_set_host(metadata, host);
    ue_communication_metadata_set_port(metadata, port);
    ue_communication_metadata_set_type(metadata, UNKNOWNECHO_COMMUNICATION_SOCKET);

    return metadata;
}
