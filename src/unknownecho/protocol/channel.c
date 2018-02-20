#include <unknownecho/protocol/channel.h>
#include <unknownecho/system/alloc.h>

ue_channel *ue_channel_create() {
    ue_channel *channel;

    ue_safe_alloc(channel, ue_channel, 1);
    channel->channel_type = UNKNOWNECHO_CHANNEL_CLIENT;
    channel->established = false;
    channel->tls_enabled = true;
    channel->pgp_enabled = true;
    channel->send_callback = NULL;
    channel->receive_callback = NULL;
    channel->relay_points = NULL;
    channel->relay_points_number = 0;
    channel->communicating = false;
    channel->id = -1;

    return channel;
}

void ue_channel_destroy(ue_channel *channel) {
    unsigned short int i;

    if (channel) {
        if (channel->relay_points) {
            for (i = 0; i < channel->relay_points_number; i++) {
                ue_relay_point_destroy(channel->relay_points[i]);
            }
            ue_safe_free(channel->relay_points);
        }
        ue_safe_free(channel);
    }
}

bool ue_channel_add_relay_point(ue_channel *channel, ue_relay_point *relay_point) {
    if (!channel->relay_points) {
        ue_safe_alloc(channel->relay_points, ue_relay_point *, 1);
    } else {
        ue_safe_realloc(channel->relay_points, ue_relay_point *, channel->relay_points_number, 1);
    }
    channel->relay_points[channel->relay_points_number] = relay_point;
    channel->relay_points_number++;

    return true;
}

void ue_channel_enable_tls(ue_channel *channel, bool enable) {
    channel->tls_enabled = enable;
}

void ue_channel_enable_pgp(ue_channel *channel, bool enable) {
    channel->pgp_enabled = enable;
}

void ue_channel_set_send_callback(ue_channel *channel, bool (*send_callback)(ue_message *message)) {
    channel->send_callback = send_callback;
}

void ue_channel_set_receive_callback(ue_channel *channel, bool (*receive_callback)(ue_message *message)) {
    channel->receive_callback = receive_callback;
}

void ue_channel_set_type(ue_channel *channel, ue_channel_type channel_type) {
    channel->channel_type = channel_type;
}
