#include <unknownecho/init.h>
#include <unknownecho/bool.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/protocol/protocol.h>
#include <unknownecho/protocol/channel.h>
#include <unknownecho/protocol/relay_point.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/time/sleep.h>
#include <unknownecho/string/string_utility.h>

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

ue_channel *channel;

void handle_signal(int sig, void (*h)(int), int options) {
    struct sigaction s;

    s.sa_handler = h;
    sigemptyset(&s.sa_mask);
    s.sa_flags = options;
    if (sigaction(sig, &s, NULL) < 0) {
        ue_stacktrace_push_errno();
    }
}

void shutdown_communication(int sig) {
    ue_logger_trace("Signal received %d", sig);
    channel->communicating = false;
}

bool send_callback(ue_message *message) {
    char *my_message;
    bool r;

    my_message = ue_string_create_from("Hello world !");

    r = ue_message_set_source_nickname(message, "Swa") &&
        ue_message_set_content_char(message, my_message);

    ue_safe_free(my_message);

    return r;
}

bool receive_callback(ue_message *message) {
    if (!message || !message->source_nickname || !message->content) {
        printf("Empty message !\n");
        return false;
    }

    printf("'%s' sent to me : '%s'\n", message->source_nickname, message->content);
    return true;
}

int main() {
    ue_global_context *global_context;
    ue_relay_point *server_relay;
    unsigned short int channel_id;

    global_context = NULL;
    channel = NULL;
    server_relay = NULL;

    ue_init();

    handle_signal(SIGINT, shutdown_communication, 0);
    handle_signal(SIGPIPE, SIG_IGN, SA_RESTART);

    /* Create the global context of the protocol */
    global_context = ue_global_context_create();

     /* Create a thread-safe channel, that use TLS and PGP per default */
    channel = ue_channel_create();
    ue_channel_set_send_callback(channel, send_callback);
    ue_channel_set_receive_callback(channel, receive_callback);
    ue_channel_set_type(channel, UNKNOWNECHO_CHANNEL_CLIENT);

    /* Configure the relay point */
    server_relay = ue_relay_point_create();
    ue_relay_point_set_host(server_relay, "127.0.0.1");
    ue_relay_point_set_port(server_relay, 5001);

    /* Add all relay points */
    ue_channel_add_relay_point(channel, server_relay);

    /* Establish the communication */
    if ((channel_id = ue_protocol_establish(global_context, channel)) == -1) {
        ue_stacktrace_push_msg("Failed to establish channel connection");
        goto clean_up;
    }

    /* Is the communication established ? */
    if (!ue_protocol_is_established(global_context, channel_id)) {
        /* Error handling */
    }

    /* Start messages exchange */
    ue_protocol_start(global_context, channel_id);

    ue_protocol_wait(global_context);

    /* Stop properly the communication */
    ue_protocol_stop(global_context, channel_id);

clean_up:
    ue_global_context_destroy(global_context);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
