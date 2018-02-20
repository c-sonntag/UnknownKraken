#ifndef UNKNOWNECHO_CHANNEL_H
#define UNKNOWNECHO_CHANNEL_H

#include <unknownecho/bool.h>
#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/protocol/message.h>
#include <unknownecho/protocol/server_channel.h>
#include <unknownecho/protocol/client_channel.h>

typedef enum {
    UNKNOWNECHO_CHANNEL_CLIENT,
    UNKNOWNECHO_CHANNEL_SERVER,
    UNKNOWNECHO_CHANNEL_CLIENT_SERVER
} ue_channel_type;

typedef struct {
    /* Settings */

    /* A channel can be a client, a server, or both */
    ue_channel_type channel_type;

    /* True if the connection istablished with all relay points */
    bool established;

    /* True if TLS connection is enable (end-to-end) */
    bool tls_enabled;

    /* True if PGP encryption is enable (end-to-end) */
    bool pgp_enabled;

    /* True if channel is currently communicating */
    bool communicating;

    /* User provide the send callback (with raw data) */
    bool (*send_callback)(ue_message *message);

    /* User provide the receive callback (with raw data) */
    bool (*receive_callback)(ue_message *message);

    /* List of relay points */
    ue_relay_point **relay_points;
    unsigned short int relay_points_number;

    /* Used with channel_type equal to UNKNOWNECHO_CHANNEL_SERVER or UNKNOWNECHO_CHANNEL_CLIENT_SERVER */
    ue_server_channel *server_channel;

    /* Used with channel_type equal to UNKNOWNECHO_CHANNEL_CLIENT or UNKNOWNECHO_CHANNEL_CLIENT_SERVER */
    ue_client_channel *client_channel;

    unsigned short int id;
} ue_channel;

ue_channel *ue_channel_create();

void ue_channel_destroy(ue_channel *channel);

bool ue_channel_add_relay_point(ue_channel *channel, ue_relay_point *relay_point);

void ue_channel_enable_tls(ue_channel *channel, bool enable);

void ue_channel_enable_pgp(ue_channel *channel, bool enable);

void ue_channel_set_send_callback(ue_channel *channel, bool (*send_callback)(ue_message *message));

void ue_channel_set_receive_callback(ue_channel *channel, bool (*receive_callback)(ue_message *message));

void ue_channel_set_type(ue_channel *channel, ue_channel_type channel_type);

#endif
