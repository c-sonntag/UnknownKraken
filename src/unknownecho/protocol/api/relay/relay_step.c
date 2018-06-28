#include <unknownecho/protocol/api/relay/relay_step.h>
#include <ei/ei.h>

#include <stdarg.h>

ue_relay_step *ue_relay_step_create(ue_communication_metadata *target_communication_metadata,
    uecm_crypto_metadata *our_crypto_metadata, uecm_crypto_metadata *target_crypto_metadata) {

    ue_relay_step *step;

    ei_check_parameter_or_return(target_communication_metadata);

    ueum_safe_alloc(step, ue_relay_step, 1);
    step->target_communication_metadata = target_communication_metadata;
    step->our_crypto_metadata = our_crypto_metadata;
    step->target_crypto_metadata = target_crypto_metadata;

    return step;
}

ue_relay_step *ue_relay_step_create_from_step(ue_relay_step *step) {
    ue_relay_step *copy;

    ueum_safe_alloc(copy, ue_relay_step, 1);
    copy->target_communication_metadata = ue_communication_metadata_copy(step->target_communication_metadata);
    copy->our_crypto_metadata = step->our_crypto_metadata;
    copy->target_crypto_metadata = step->target_crypto_metadata;

    return copy;
}

ue_relay_step **ue_relay_steps_create(int step_number, ...) {
    ue_relay_step **steps;
    va_list ap;
    int i;

    ei_check_parameter_or_return(step_number > 0);

    ueum_safe_alloc(steps, ue_relay_step *, step_number);

    va_start(ap, step_number);

    for (i = 0; i < step_number; i++) {
        steps[i] = va_arg(ap, ue_relay_step *);
    }

    va_end(ap);

    return steps;
}

void ue_relay_step_destroy(ue_relay_step *step) {
    if (step) {
        ue_communication_metadata_destroy(step->target_communication_metadata);
        ueum_safe_free(step);
    }
}

void ue_relay_step_destroy_all(ue_relay_step *step) {
    if (step) {
        ue_communication_metadata_destroy(step->target_communication_metadata);
        uecm_crypto_metadata_destroy_all(step->our_crypto_metadata);
        uecm_crypto_metadata_destroy_all(step->target_crypto_metadata);
        ueum_safe_free(step);
    }
}

ue_communication_metadata *ue_relay_step_get_target_communication_metadata(ue_relay_step *step) {
    if (!ue_relay_step_is_valid(step)) {
        ei_stacktrace_push_msg("Specified step ptr is invalid");
        return NULL;
    }

    return step->target_communication_metadata;
}

uecm_crypto_metadata *ue_relay_step_get_our_crypto_metadata(ue_relay_step *step) {
    if (!ue_relay_step_is_valid(step)) {
        ei_stacktrace_push_msg("Specified step ptr is invalid");
        return NULL;
    }

    return step->our_crypto_metadata;
}

uecm_crypto_metadata *ue_relay_step_get_target_crypto_metadata(ue_relay_step *step) {
    if (!ue_relay_step_is_valid(step)) {
        ei_stacktrace_push_msg("Specified step ptr is invalid");
        return NULL;
    }

    return step->target_crypto_metadata;
}

void ue_relay_step_print(ue_relay_step *step, FILE *fd) {
    fprintf(fd, "Target communication metadata: [");
    ue_communication_metadata_print(step->target_communication_metadata, fd);
    fprintf(fd, "]\n");
}

bool ue_relay_step_is_valid(ue_relay_step *step) {
    if (!step) {
        ei_stacktrace_push_msg("Specified step ptr is null");
        return false;
    }

    if (!ue_communication_metadata_is_valid(step->target_communication_metadata)) {
        ei_stacktrace_push_msg("The communication metadata of specified step is invalid");
        return false;
    }

    if (!step->target_crypto_metadata) {
        ei_logger_warn("Specified step doesn't provide target crypto metadata");
    }

    return true;
}
