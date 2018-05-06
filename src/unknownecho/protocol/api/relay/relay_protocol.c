#include <unknownecho/protocol/api/relay/relay_protocol.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/fileSystem/file_utility.h>

ue_relay_protocol_context *ue_relay_protocol_init_from_string(const char *string) {
    //ue_relay_protocol_context *context;

    ue_check_parameter_or_return(string);

    ue_stacktrace_push_msg("Not implemented");

    return NULL;
}

ue_relay_protocol_context *ue_relay_protocol_init_from_route(ue_relay_step **steps, unsigned short int steps_number) {
    ue_check_parameter_or_return(steps);
    ue_check_parameter_or_return(steps_number > 0);

    ue_stacktrace_push_msg("Not implemented");

    return NULL;
}

ue_relay_protocol_context *ue_relay_protocol_init_from_file(const char *file_path) {
    ue_check_parameter_or_return(file_path);

    ue_stacktrace_push_msg("Not implemented");

    return NULL;
}

void ue_relay_protocol_destroy(ue_relay_protocol_context *context) {
    if (context) {
        ue_relay_route_destroy(context->route);
        ue_safe_free(context);
    }
}

bool ue_relay_protocol_establish_dry_run(ue_relay_protocol_context *context) {
    bool result;

    ue_check_parameter_or_return(context);

    result = false;

    result = true;

    return result;
}

bool ue_relay_protocol_establish(ue_relay_protocol_context *context) {
    bool result;

    ue_check_parameter_or_return(context);

    result = false;

    result = true;

    return result;
}

bool ue_relay_protocol_close(ue_relay_protocol_context *context) {
    bool result;

    ue_check_parameter_or_return(context);

    result = false;

    result = true;

    return result;
}

bool ue_relay_protocol_send(ue_relay_protocol_context *context) {
    bool result;

    ue_check_parameter_or_return(context);

    result = false;

    result = true;

    return result;
}

bool ue_relay_protocol_receive(ue_relay_protocol_context *context) {
    bool result;

    ue_check_parameter_or_return(context);

    result = false;

    result = true;

    return result;
}
