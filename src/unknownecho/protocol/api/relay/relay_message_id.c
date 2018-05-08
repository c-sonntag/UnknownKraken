#include <unknownecho/protocol/api/relay/relay_message_id.h>

bool ue_relay_message_id_is_valid(int id) {
    return id == UNKNOWNECHO_RELAY_MESSAGE_ID_ESTABLISH ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_DISCONNECT ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_SEND ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_SEND_ACK ||
        id == UNKNOWNECHO_RELAY_MESSAGE_ID_RECEIVE_ACK;
}
