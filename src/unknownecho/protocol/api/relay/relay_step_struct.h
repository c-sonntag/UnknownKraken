#ifndef UNKNOWNECHO_RELAY_STEP_STRUCT_H
#define UNKNOWNECHO_RELAY_STEP_STRUCT_H

#include <unknownecho/network/api/communication/communication_metadata.h>
#include <uecm/uecm.h>

typedef struct {
    ue_communication_metadata *target_communication_metadata;
    uecm_crypto_metadata *our_crypto_metadata;
    uecm_crypto_metadata *target_crypto_metadata;
} ue_relay_step;

#endif
