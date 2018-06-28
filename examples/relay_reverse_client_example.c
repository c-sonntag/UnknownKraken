#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/protocol/api/relay/relay_client.h>
#include <unknownecho/protocol/api/relay/relay_step.h>
#include <unknownecho/protocol/api/relay/relay_route.h>
#include <unknownecho/network/api/communication/communication_metadata.h>
#include <unknownecho/network/factory/communication_metadata_factory.h>
#include <unknownecho/byte/byte_stream.h>
#include <unknownecho/byte/byte_writer.h>
#include <unknownecho/crypto/api/crypto_metadata.h>
#include <unknownecho/crypto/factory/crypto_metadata_factory.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/bool.h>
#include <unknownecho/console/input.h>

#include <unknownecho/thread/thread_id_struct.h>
#include <unknownecho/thread/thread.h>
#include <unknownecho/thread/thread_mutex.h>
#include <unknownecho/thread/thread_cond.h>

#include <ei/ei.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

typedef enum {
    READING_STATE,
    WRITING_STATE,
    CLOSING_STATE
} ue_data_transmission_state;

typedef struct {
    ue_relay_client *client;
    ue_thread_mutex *mutex;
    ue_thread_cond *cond;
    ue_data_transmission_state transmission_state;
    bool running;
    ue_thread_id *read_consumer_thread, *write_consumer_thread;
} global_context;

ue_crypto_metadata **remote_crypto_metadatas = NULL;
int remote_crypto_metadatas_number = 0;
global_context context;

/* The file descriptor of the output consola */
int fds[2];

int client_id = 1;

#define try_or_clean_up(exp, error_message, label) \
    if (!(exp)) { \
        ei_stacktrace_push_msg("%s", error_message); \
        goto label; \
    } \

static bool load_crypto_metadata_from_uid(ue_crypto_metadata **crypto_metadata, const char *uid) {
    if (!(*crypto_metadata = ue_crypto_metadata_create_empty())) {
        ei_stacktrace_push_msg("Failed to create empty crypto metadata object for client1");
        return false;
    }

    if (!ue_crypto_metadata_read_certificates(*crypto_metadata, "out/public", uid)) {
        ue_crypto_metadata_destroy(*crypto_metadata);
        ei_stacktrace_push_msg("Failed to read certificates of target %s", uid);
        return false;
    }

    return true;
}

static bool load_crypto_metadatas_as_client1(ue_crypto_metadata **client1_crypto_metadata,
    ue_crypto_metadata **client2_crypto_metadata, ue_crypto_metadata **server1_crypto_metadata,
    ue_crypto_metadata **server2_crypto_metadata) {

    if (!(*client1_crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client1", "password"))) {
        
        ei_stacktrace_push_msg("Failed to get our crypto metadata");
        goto clean_up_fail;
    }

    try_or_clean_up(load_crypto_metadata_from_uid(client2_crypto_metadata, "client2"),
        "Failed to load client2 crypto metadata", clean_up_fail);

    try_or_clean_up(load_crypto_metadata_from_uid(server1_crypto_metadata, "server1"),
        "Failed to load server1 crypto metadata", clean_up_fail);

    try_or_clean_up(load_crypto_metadata_from_uid(server2_crypto_metadata, "server2"),
        "Failed to load server2 crypto metadata", clean_up_fail);

    return true;

clean_up_fail:
    return false;
}

static bool load_crypto_metadatas_as_client2(ue_crypto_metadata **client1_crypto_metadata,
    ue_crypto_metadata **client2_crypto_metadata, ue_crypto_metadata **server1_crypto_metadata,
    ue_crypto_metadata **server2_crypto_metadata) {

    if (!(*client2_crypto_metadata = ue_crypto_metadata_write_if_not_exist("out/private", "out/public",
        "client2", "password"))) {
        
        ei_stacktrace_push_msg("Failed to get our crypto metadata");
        goto clean_up_fail;
    }

    try_or_clean_up(load_crypto_metadata_from_uid(client1_crypto_metadata, "client1"),
        "Failed to load client1 crypto metadata", clean_up_fail);

    try_or_clean_up(load_crypto_metadata_from_uid(server1_crypto_metadata, "server1"),
        "Failed to load server1 crypto metadata", clean_up_fail);

    try_or_clean_up(load_crypto_metadata_from_uid(server2_crypto_metadata, "server2"),
        "Failed to load server2 crypto metadata", clean_up_fail);

    return true;

clean_up_fail:
    return false;
}

ue_relay_route *generate_route_as_client1(ue_crypto_metadata *client1_crypto_metadata, ue_crypto_metadata 
    *client2_crypto_metadata, ue_crypto_metadata *server1_crypto_metadata, ue_crypto_metadata
    *server2_crypto_metadata) {
    
    ue_relay_route *route;

    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            3,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "127.0.0.1", 5001),
                client1_crypto_metadata, server1_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "127.0.0.1", 5002),
                client1_crypto_metadata, server2_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client2:0:127.0.0.1:5002:1"),
                client1_crypto_metadata, client2_crypto_metadata)
        ),
        3))) {

        ei_stacktrace_push_msg("Failed to create route client1 -> server1 -> server2 -> client2");
        return NULL;
    }

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Generated route for client2 is invalid");
        return NULL;
    }

    return route;
}

ue_relay_route *generate_route_as_client2(ue_crypto_metadata *client1_crypto_metadata, ue_crypto_metadata 
    *client2_crypto_metadata, ue_crypto_metadata *server1_crypto_metadata, ue_crypto_metadata
    *server2_crypto_metadata) {
    
    ue_relay_route *route;

    if (!(route = ue_relay_route_create(
        ue_relay_steps_create(
            3,
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server2", "127.0.0.1", 5002),
                client2_crypto_metadata, server2_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_socket_type("server1", "127.0.0.1", 5001),
                client2_crypto_metadata, server1_crypto_metadata),
            ue_relay_step_create(ue_communication_metadata_create_from_string("client1:0:127.0.0.1:5001:1"),
                client2_crypto_metadata, client1_crypto_metadata)
        ),
        3))) {

        ei_stacktrace_push_msg("Failed to create route client2 -> server2 -> server1 -> client1");
        return NULL;
    }

    if (!ue_relay_route_is_valid(route)) {
        ei_stacktrace_push_msg("Generated route for client2 is invalid");
        return NULL;
    }

    return route;
}

static bool send_message(ue_byte_stream *message_to_send) {
    bool result;

    ei_check_parameter_or_return(message_to_send);
    ei_check_parameter_or_return(!ue_byte_stream_is_empty(message_to_send));

    result = false;

    ue_thread_mutex_lock(context.mutex);
    context.transmission_state = WRITING_STATE;
    result = ue_relay_client_send_message(context.client, message_to_send);
    context.transmission_state = READING_STATE;
    ue_thread_cond_signal(context.cond);
    ue_thread_mutex_unlock(context.mutex);

    return result;
}

static bool receive_message(ue_byte_stream *received_message) {
    bool result;

    ue_thread_mutex_lock(context.mutex);
    while (context.transmission_state == WRITING_STATE) {
        ue_thread_cond_wait(context.cond, context.mutex);
    }
    ue_thread_mutex_unlock(context.mutex);

    ei_logger_debug("1.0");
    result = ue_relay_client_receive_message(context.client, received_message);
    //ei_logger_debug("1.1");
    return result;
}

static void read_consumer(void *parameter) {
    ue_byte_stream *received_message;

    received_message = ue_byte_stream_create();

    while (context.running) {
        if (!receive_message(received_message)) {
            ei_logger_stacktrace("Failed to receive message");
            ei_stacktrace_clean_up();
        } else {
            //ei_logger_debug("1.2");
            if (memcmp(ue_byte_stream_get_data(received_message), "-s", strlen("-s")) == 0) {
                context.running = false;
                break;
            }
            //ei_logger_debug("1.3");
            // Append \n and \0 to correctly print the message on the consola
            if (!ue_byte_writer_append_bytes(received_message, (unsigned char *)"\n\0", 2)) {
                ei_stacktrace_push_msg("Failed to write \n\0 to printer");
                ei_logger_stacktrace("Failed to parse received message with following stacktrace:");
                ei_stacktrace_clean_up();
                continue;
            }
            //ei_logger_debug("1.4");
            write(fds[1], ue_byte_stream_get_data(received_message), ue_byte_stream_get_size(received_message));
            ei_logger_debug("1.5");
        }
    }

    ue_byte_stream_destroy(received_message);
}

static void write_consumer(void *parameter) {
    char *input;
    ue_byte_stream *message;

    if (!(message = ue_byte_stream_create())) {
        ei_stacktrace_push_msg("Failed to create empty byte stream");
        return;
    }

    while (context.running) {
        input = ue_input_string(">");

        if (!input) {
            continue;
        }

        if (strcmp(input, "-q") == 0) {
            context.running = false;
            break;
        }

        ue_byte_stream_clean_up(message);
        ue_byte_writer_append_string(message, input);

        if (!send_message(message)) {
            ei_logger_stacktrace("Failed to send message to server");
        } else {
            ei_logger_info("Message sent.");
        }

        ue_safe_free(input);
    }

    ue_safe_free(input);
    ue_byte_stream_destroy(message);
}

int main(int argc, char **argv) {
    ue_relay_route *route;
    ue_crypto_metadata *client1_crypto_metadata, *client2_crypto_metadata, *server1_crypto_metadata,
        *server2_crypto_metadata;
    ue_communication_metadata *our_communication_metadata;
    int child_pid;

    if (argc != 2) {
        fprintf(stdout, "Usage: %s <1|2> \n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }
    ei_logger_info("UnknownEchoLib is correctly initialized.");

    route = NULL;
    client1_crypto_metadata = NULL;
    client2_crypto_metadata = NULL;
    server1_crypto_metadata = NULL;
    server2_crypto_metadata = NULL;
    our_communication_metadata = NULL;
    fds[1] = -1;

    /**
     * Create a pipe for interprocess communication,
     * in order to communicate deciphered messages to
     * second consola, to print them.
     * Only working on UNIX system.
     */
    if (pipe(fds) == -1) {
		ei_stacktrace_push_errno();
        goto clean_up;
    }

    /**
     * Fork (duplicate) the process.
     * The second process is just a consola that print
     * deciphered messages.
     */
    child_pid = fork();

    /* Check if fork() failed. */
    if (child_pid == -1) {
		ei_stacktrace_push_errno();
        goto clean_up;
    }

    /**
     * If child_pid is equal to 0, then
     * the current process is the child,
     * then the process is just an xtern consola
     * that will print messages.
     */
    if (child_pid == 0) {
        /* Close the unused parent process */
        close(fds[1]);
        char f[PATH_MAX + 1];
        sprintf(f, "/dev/fd/%d", fds[0]);
        execlp("xterm", "xterm", "-e", "cat", f, NULL);
        client2_crypto_metadata = NULL;
		ei_stacktrace_push_errno();
        goto clean_up;
    }

    /**
     * If child_pid is > to 0, then the current
     * process is the parent, so it close
     */
    if (child_pid != 0) {
        /* Close the unused child process */
        close(fds[0]);

        context.mutex = ue_thread_mutex_create();
        context.cond = ue_thread_cond_create();
        
        context.client = NULL;
        context.transmission_state = READING_STATE;
        context.running = true;

        if (atoi(argv[1]) == 1) {
            try_or_clean_up(load_crypto_metadatas_as_client1(&client1_crypto_metadata, &client2_crypto_metadata,
                &server1_crypto_metadata, &server2_crypto_metadata), "Failed to load crypto metadatas", clean_up);

            try_or_clean_up(route = generate_route_as_client1(client1_crypto_metadata, client2_crypto_metadata,
                server1_crypto_metadata, server2_crypto_metadata), "Failed to generate route as client 1", clean_up);

            our_communication_metadata = ue_communication_metadata_create_socket_type("client1", "127.0.0.1", 0);

            ei_logger_info("client1 route:");

        }
        else if (atoi(argv[1]) == 2) {
            try_or_clean_up(load_crypto_metadatas_as_client2(&client1_crypto_metadata, &client2_crypto_metadata,
                &server1_crypto_metadata, &server2_crypto_metadata), "Failed to load crypto metadatas", clean_up);

            try_or_clean_up(route = generate_route_as_client2(client1_crypto_metadata, client2_crypto_metadata,
                server1_crypto_metadata, server2_crypto_metadata), "Failed to generate route as client 2", clean_up);

            our_communication_metadata = ue_communication_metadata_create_socket_type("client2", "127.0.0.1", 0);

            ei_logger_info("client2 route:");
        } else {
            ei_stacktrace_push_msg("Unknown client id");
            goto clean_up;
        }

        client_id = atoi(argv[1]);

        ue_relay_route_print(route, stdout);

        if (!ue_relay_route_is_valid(route)) {
            ei_stacktrace_push_msg("New route is invalid");
            goto clean_up;
        }

        if (!(context.client = ue_relay_client_create_from_route(our_communication_metadata, route))) {
            ei_stacktrace_push_msg("Failed to create new relay client");
            goto clean_up;
        }

        if (!ue_relay_client_is_valid(context.client)) {
            ei_stacktrace_push_msg("New relay client is invalid");
            goto clean_up;
        }
        ei_logger_info("New relay client is valid");

    _Pragma("GCC diagnostic push")
    _Pragma("GCC diagnostic ignored \"-Wpedantic\"")
        context.read_consumer_thread = ue_thread_create(read_consumer, NULL);
        if (client_id == 1) {
            context.write_consumer_thread = ue_thread_create(write_consumer, NULL);
        }
    _Pragma("GCC diagnostic pop")

        ue_thread_join(context.read_consumer_thread, NULL);
        if (client_id == 1) {
            ue_thread_join(context.write_consumer_thread, NULL);
        }
    }

clean_up:
    /* Close the consola */
    if (fds[1] != 1) {
        close(fds[1]);
    }
    if (child_pid != 0) {
        ue_communication_metadata_destroy(our_communication_metadata);
        ue_relay_client_destroy(context.client);
        ue_thread_mutex_destroy(context.mutex);
        ue_thread_cond_destroy(context.cond);
        ue_crypto_metadata_destroy_all(client1_crypto_metadata);
        ue_crypto_metadata_destroy_all(client2_crypto_metadata);
        ue_crypto_metadata_destroy_all(server1_crypto_metadata);
        ue_crypto_metadata_destroy_all(server2_crypto_metadata);
        ue_relay_route_destroy(route);
    }
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
