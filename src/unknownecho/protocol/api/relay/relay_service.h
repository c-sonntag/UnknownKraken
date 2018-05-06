#ifndef UNKNOWNECHO_RELAY_SERVICE_H
#define UNKNOWNECHO_RELAY_SERVICE_H

#include <unknownecho/protocol/api/relay/relay_service_struct.h>
#include <unknownecho/protocol/api/relay/relay_client_struct.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/bool.h>

bool ue_relay_service_init(ue_communication_metadata *server_communication_metadata);

bool ue_relay_service_uninit();

bool ue_relay_service_start();

bool ue_relay_service_stop();

bool ue_relay_service_is_valid();

const char *ue_relay_service_status();

const char *ue_relay_service_human_readable_status();

bool ue_relay_service_running();

bool ue_relay_service_attach_client(ue_relay_client *relay_client);

#endif
