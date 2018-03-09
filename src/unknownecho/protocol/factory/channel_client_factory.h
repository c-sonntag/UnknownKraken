#ifndef UNKNOWNECHO_CHANNEL_CLIENT_FACTORY_H
#define UNKNOWNECHO_CHANNEL_CLIENT_FACTORY_H

#include <unknownecho/protocol/api/channel/channel_client_struct.h>
#include <unknownecho/bool.h>
#include <unknownecho/byte/byte_stream.h>

ue_channel_client *ue_channel_client_create_default(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ue_byte_stream *printer));

#endif
