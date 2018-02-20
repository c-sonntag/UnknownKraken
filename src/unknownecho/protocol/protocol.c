#include <unknownecho/protocol/protocol.h>
#include <unknownecho/protocol/message.h>
#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/time/sleep.h>

#include <stddef.h>

static bool is_valid_channel_id(ue_global_context *global_context, unsigned short int channel_id) {
    return channel_id >= 0 && channel_id <= UNKNOWNECHO_CHANNELS_MAX;
}

bool receive_message(ue_channel *channel, ue_message *message) {
    // receive data
    // decrypt data
    // set decrypted data to message
    ue_millisleep(100);
    ue_logger_trace("%s", (char *)__func__);
    //stacktrace_push_msg("Not implemented");
    return true;
}

bool send_message(ue_channel *channel, ue_message *message) {
    // encrypt message->data
    // send_data
    ue_millisleep(100);
    ue_logger_trace("%s", (char *)__func__);
    //stacktrace_push_msg("Not implemented");
    return true;
}

void communicate(void *param) {
    ue_message *message;
    ue_channel *channel;

    message = ue_message_create();

    channel = (ue_channel *)param;

    if (!channel) {
        ue_logger_error("Invalid channel");
        return;
    }

    // Create read and write thread consumer
    //

    /* Simple process without error handling and callbacks */
    if (channel->channel_type == UNKNOWNECHO_CHANNEL_CLIENT) {
        while (channel->communicating && channel->client_channel->running) {
            ue_client_channel_wait(channel->client_channel);
        }
        ue_client_channel_destroy(channel->client_channel);
    } else if (channel->channel_type == UNKNOWNECHO_CHANNEL_SERVER) {
        ue_server_channel_start(channel->server_channel);
        ue_server_channel_destroy(channel->server_channel);
    } else {
        ue_logger_error("Unknown channel type");
    }

    //while (channel->communicating) {
        //receive_message(channel, message);
        //channel->receive_callback(message);
        //channel->send_callback(message);
        //send_message(channel, message);
        //message_clean_up(message);
    //}

    ue_message_destroy(message);

    channel->established = false;
}

unsigned short int ue_protocol_establish(ue_global_context *global_context, ue_channel *channel) {
    unsigned short int channel_id;

    if (channel->relay_points_number < 1) {
        ue_stacktrace_push_msg("At least 1 relay point is required");
        return -1;
    }

    global_context->channels[global_context->channels_number] = channel;
    channel_id = global_context->channels_number;
    global_context->channels_number++;

    if (channel->channel_type == UNKNOWNECHO_CHANNEL_CLIENT) {
        if (!(channel->client_channel = ue_client_channel_create(channel->relay_points[0]))) {
            ue_stacktrace_push_msg("Failed to create client channel with first relay point");
            return -1;
        }
        ue_client_channel_start(channel->client_channel);
    } else if (channel->channel_type == UNKNOWNECHO_CHANNEL_SERVER) {
        channel->server_channel = ue_server_channel_create(channel->relay_points[0]);
    }

    channel->established = true;
    channel->id = channel_id;

    return channel_id;
}

bool ue_protocol_is_established(ue_global_context *global_context, unsigned short int channel_id) {
    if (!is_valid_channel_id(global_context, channel_id)) {
        ue_stacktrace_push_msg("Specified channel id isn't valid");
        return false;
    }

    /* verify all the chain ? */

    return global_context->channels[channel_id]->established;
}

bool ue_protocol_start(ue_global_context *global_context, unsigned short int channel_id) {
    if (!is_valid_channel_id(global_context, channel_id)) {
        ue_stacktrace_push_msg("Specified channel id isn't valid");
        return false;
    }

    global_context->channels[channel_id]->communicating = true;

    _Pragma("GCC diagnostic push");
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"");
        global_context->thread_channels[channel_id] = ue_thread_create(communicate, global_context->channels[channel_id]);
    _Pragma("GCC diagnostic pop");

    return true;
}

void ue_protocol_wait(ue_global_context *global_context) {
    unsigned short int i;

    if (global_context->thread_channels) {
        for (i = 0; i < global_context->channels_number; i++) {
            ue_thread_join(global_context->thread_channels[i], NULL);
        }
    }
}

void ue_protocol_stop_signal(ue_global_context *global_context, unsigned short int channel_id) {
    if (!is_valid_channel_id(global_context, channel_id)) {
        ue_logger_warn("Specified channel id isn't valid");
        return;
    }

    if (global_context->channels[channel_id]->channel_type == UNKNOWNECHO_CHANNEL_SERVER) {
        global_context->channels[channel_id]->server_channel->server->running = false;
        ue_logger_trace("global_context->channels[%d]->server_channel->server->running set to false", channel_id);
    }
    global_context->channels[channel_id]->communicating = false;
}

void ue_protocol_stop(ue_global_context *global_context, unsigned short int channel_id) {
    if (!is_valid_channel_id(global_context, channel_id)) {
        ue_logger_warn("Specified channel id isn't valid");
        return;
    }

    global_context->channels[channel_id]->communicating = false;

    while (global_context->channels[channel_id]->established);

    ue_safe_free(global_context->thread_channels[channel_id]);
}

bool ue_protocol_is_communicating(ue_global_context *global_context, unsigned short int channel_id) {
    if (!is_valid_channel_id(global_context, channel_id)) {
        ue_stacktrace_push_msg("Specified channel id isn't valid");
        return false;
    }

    return global_context->channels[channel_id]->communicating;
}
