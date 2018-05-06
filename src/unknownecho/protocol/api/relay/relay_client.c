#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/api/communication/communication.h>
#include <unknownecho/network/factory/communication_factory.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_relay_client *ue_relay_client_create(ue_relay_step *step) {
    ue_relay_client *relay_client;
    void *client_connection_parameters;
    ue_communication_metadata *target_communication_metadata;

    /* Check if relay objet is valid, recursively */
    if (!ue_relay_step_is_valid(step)) {
        ue_stacktrace_push_msg("Specified step is invalid");
        return NULL;
    }

    /* Get the communication metadata of the target */
    target_communication_metadata = ue_relay_step_get_target_communication_metadata(step);

    /* Alloc the client objet */
    ue_safe_alloc(relay_client, ue_relay_client, 1);
    relay_client->communication_context = NULL;
    relay_client->connection = NULL;

    /* Create the communication context from the type of communication specified in the metadata of target */
    relay_client->communication_context = ue_communication_build_from_type(ue_communication_metadata_get_type(target_communication_metadata));

    /**
     * Build client connection parameters from communication builder, with host and port of target communication metadata
     * or record an error if it's failed.
     * @warning At this point of the POC, the optional third arg of secure layer isn't used, nor the crypto_metadata of the
     * step object.
     **/
    if (!(client_connection_parameters = ue_communication_build_client_connection_parameters(relay_client->communication_context, 2,
        ue_communication_metadata_get_host(target_communication_metadata), ue_communication_metadata_get_port(target_communication_metadata)))) {
        ue_safe_free(relay_client);
        ue_stacktrace_push_msg("Failed to create client connection parameters context");
        goto clean_up;
    }

    /* Finally connect the client or record an error if it's failed */
    if (!(relay_client->connection = ue_communication_connect(relay_client->communication_context,
        client_connection_parameters))) {
        ue_safe_free(relay_client);
        ue_stacktrace_push_msg("Failed to connect socket to server");
        goto clean_up;
    }

clean_up:
    ue_safe_free(client_connection_parameters);
    return relay_client;
}

void ue_relay_client_destroy(ue_relay_client *client) {
    if (client) {
        ue_communication_client_connection_destroy(client->communication_context, client->connection);
        ue_communication_destroy(client->communication_context);
        ue_safe_free(client);
    }
}

bool ue_relay_client_is_valid(ue_relay_client *client) {
    return client && ue_communication_context_is_valid(client->communication_context) &&
        client->connection && (client->communication_context->communication_client_connection_is_established_impl ?
        client->communication_context->communication_client_connection_is_established_impl(client->connection) : true);
}

ue_communication_context *ue_relay_client_get_communication_context(ue_relay_client *client) {
    /* Check first if the specified client is valid */
    if (!ue_relay_client_is_valid(client)) {
        ue_stacktrace_push_msg("Specified client isn't valid. The connection is maybe isn't established");
        return NULL;
    }

    return client->communication_context;
}

void *ue_relay_client_get_connection(ue_relay_client *client) {
    /* Check first if the specified client is valid */
    if (!ue_relay_client_is_valid(client)) {
        ue_stacktrace_push_msg("Specified client isn't valid. The connection is maybe isn't established");
        return NULL;
    }

    return client->connection;
}
