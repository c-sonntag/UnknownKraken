#include <unknownecho/protocol/factory/channel_client_factory.h>
#include <unknownecho/protocol/api/channel/channel_client_parameters.h>
#include <unknownecho/protocol/api/channel/channel_client_parameters_struct.h>
#include <unknownecho/errorHandling/logger.h>

static bool initialization_begin_callback(void *user_context) {
    ue_logger_trace("Initialization begin");
    return true;
}

static bool initialization_end_callback(void *user_context){
    ue_logger_trace("Initialization end");
    return true;
}

static bool uninitialization_begin_callback(void *user_context) {
    ue_logger_trace("Uninitialization begin");
    return true;
}

static bool uninitialization_end_callback(void *user_context) {
    ue_logger_trace("Uninitialization end");
    return true;
}

static bool connection_begin_callback(void *user_context) {
    ue_logger_trace("Connection begin");
    return true;
}

static bool connection_end_callback(void *user_context) {
    ue_logger_trace("Connection end");
    return true;
}

ue_channel_client *ue_channel_client_create_default(char *nickname, char *keystore_password, bool (*write_callback)(void *user_context, ue_byte_stream *printer)) {
    ue_channel_client_parameters *parameters;
    ue_channel_client *channel_client;

    parameters = ue_channel_client_parameters_create(nickname, keystore_password, write_callback);

    ue_channel_client_parameters_set_initialization_begin_callback(parameters, initialization_begin_callback);

    ue_channel_client_parameters_set_initialization_end_callback(parameters, initialization_end_callback);

    ue_channel_client_parameters_set_uninitialization_begin_callback(parameters, uninitialization_begin_callback);

    ue_channel_client_parameters_set_uninitialization_end_callback(parameters, uninitialization_end_callback);

    ue_channel_client_parameters_set_connection_begin_callback(parameters, connection_begin_callback);

    ue_channel_client_parameters_set_connection_end_callback(parameters, connection_end_callback);

    channel_client = ue_channel_client_parameters_build(parameters);

    ue_channel_client_parameters_destroy(parameters);

    return channel_client;
}
