#ifndef UNKNWOWNECHO_RELAY_STEP_H
#define UNKNWOWNECHO_RELAY_STEP_H

#include <unknownecho/protocol/api/relay/relay_step_struct.h>
#include <unknownecho/bool.h>

#include <stdio.h>

ue_relay_step *ue_relay_step_create(ue_communication_metadata *our_communication_metadata,
    ue_communication_metadata *target_communication_metadata,
    ue_crypto_metadata *our_crypto_metadata, ue_crypto_metadata *target_crypto_metadata);

ue_relay_step **ue_relay_steps_create(int step_number, ...);

void ue_relay_step_destroy(ue_relay_step *step);

void ue_relay_step_destroy_all(ue_relay_step *step);

ue_communication_metadata *ue_relay_step_get_our_communication_metadata(ue_relay_step *step);

ue_communication_metadata *ue_relay_step_get_target_communication_metadata(ue_relay_step *step);

ue_crypto_metadata *ue_relay_step_get_our_crypto_metadata(ue_relay_step *step);

ue_crypto_metadata *ue_relay_step_get_target_crypto_metadata(ue_relay_step *step);

void ue_relay_step_print(ue_relay_step *step, FILE *fd);

bool ue_relay_step_is_valid(ue_relay_step *step);

#endif
