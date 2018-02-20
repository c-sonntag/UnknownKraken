#include <unknownecho/protocol/global_context.h>
#include <unknownecho/system/alloc.h>

ue_global_context *ue_global_context_create() {
    ue_global_context *global_context;

    ue_safe_alloc(global_context, ue_global_context, 1);
    ue_safe_alloc(global_context->channels, ue_channel *, UNKNOWNECHO_CHANNELS_MAX);
    ue_safe_alloc(global_context->thread_channels, ue_thread_id *, UNKNOWNECHO_CHANNELS_MAX);
    global_context->channels_number = 0;

    return global_context;
}

void ue_global_context_destroy(ue_global_context *global_context) {
    unsigned short int i;

    if (global_context) {
        if (global_context->channels) {
            for (i = 0; i < global_context->channels_number; i++) {
                ue_channel_destroy(global_context->channels[i]);
            }
            ue_safe_free(global_context->channels);
        }
        if (global_context->thread_channels) {
            for (i = 0; i < global_context->channels_number; i++) {
                ue_safe_free(global_context->thread_channels[i]);
            }
            ue_safe_free(global_context->thread_channels);
        }
        ue_safe_free(global_context);
    }
}
