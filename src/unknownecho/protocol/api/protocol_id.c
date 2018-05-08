#include <unknownecho/protocol/api/protocol_id.h>

bool ue_protocol_id_is_valid(int id) {
    return id == UNKNOWNECHO_PROTOCOL_ID_CHANNEL ||
        id == UNKNOWNECHO_PROTOCOL_ID_RELAY;
}
