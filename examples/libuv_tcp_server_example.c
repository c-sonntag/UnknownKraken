#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>

#include <uv.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 7000
#define DEFAULT_BACKLOG 128

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_tcp_t **clients;
    int max_clients;
    int clients_number;
} tcp_clients;

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t*) req;
    ue_safe_free(wr->buf.base);
    ue_safe_free(wr);
}

/**
 * @todo check malloc return
 */
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_close(uv_handle_t* handle) {
    ue_safe_free(handle);
}

void echo_write(uv_write_t *req, int status) {
    if (status) {
        ue_stacktrace_push_msg("Write error: %s", uv_strerror(status));
    }
    free_write_req(req);
}

void echo_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    write_req_t *req;
    uv_tcp_t *server;
    tcp_clients *clients;
    int id;
    bool alloc_r;

    alloc_r = false;

    if (nread > 0) {
        ue_safe_alloc_ret(req, write_req_t, 1, alloc_r);
        if (!alloc_r) {
            ue_stacktrace_push_msg("Failed to alloc write_req_t");
            return;
        }

        /* @todo add error handling for this two functions */
        req->buf = uv_buf_init(buf->base, nread);
        uv_write((uv_write_t *)req, client, &req->buf, 1, echo_write);

        return;
    }

    if (nread < 0) {
        if (nread != UV_EOF) {
            ue_stacktrace_push_msg("Read error: %s", uv_err_name(nread));
        }
        if (!(server = client->loop->data)) {
            ue_stacktrace_push_msg("User data of loop ptr is null");
            return;
        }
        if (!(clients = server->data)) {
            ue_stacktrace_push_msg("User data of server ptr is null");
            return;
        }
        id = *(int *)client->data;
        uv_close((uv_handle_t *) client, on_close);
        if (id < 0 || id > clients->max_clients) {
            ue_stacktrace_push_msg("id value isn't valid: '%d' ; client handle is still closed", id);
            return;
        }
        clients->clients[id] = NULL;
        clients->clients_number--;
    }

    if (buf->base) {
        free(buf->base);
    }
}

void on_new_connection(uv_stream_t *server, int status) {
    tcp_clients *clients;
    uv_tcp_t *client;
    int id;
    bool alloc_r;

    if (status < 0) {
        ue_stacktrace_push_msg("New connection error: %s", uv_strerror(status));
        return;
    }

    ue_safe_alloc_ret(client, uv_tcp_t, 1, alloc_r);
    if (!alloc_r) {
        ue_stacktrace_push_msg("Failed to alloc write_req_t");
        return;
    }

    /* @todo add error handling */
    uv_tcp_init(server->loop, client);

    /* @todo add a log to record why the connection isn't accepted by the server */
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        clients = server->data;
        clients->clients[clients->clients_number] = client;
        id = clients->clients_number;
        client->data = &id;
        clients->clients_number++;
        /* @todo add error handling here */
        uv_read_start((uv_stream_t *) client, alloc_buffer, echo_read);
    } else {
        uv_close((uv_handle_t*) client, on_close);
    }
}

void ov_walk(uv_handle_t *handle, void *arg) {
    if (handle) {
        uv_close(handle, NULL);
    }
}

void on_sigint_received(uv_signal_t *handle, int signum) {
    printf("Signal received: %d\n", signum);
    if (uv_loop_close(handle->loop) == UV_EBUSY) {
        uv_walk(handle->loop, ov_walk, NULL);
    }
}

int main() {
    uv_loop_t *loop;
    struct sockaddr_in addr;
    uv_signal_t sigint;
    tcp_clients clients;
    uv_tcp_t server;
    int i, r;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    /* @todo add error handling */
    loop = uv_default_loop();

    /* @todo add error handling */
    uv_tcp_init(loop, &server);

    /* @todo add error handling */
    uv_signal_init(loop, &sigint);

    /* @todo add error handling */
    uv_signal_start(&sigint, on_sigint_received, SIGINT);

    /* @todo add error handling */
    uv_ip4_addr("0.0.0.0", DEFAULT_PORT, &addr);

    /* @todo add error handling */
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);

    loop->data = &server;

    server.data = &clients;
    clients.max_clients = DEFAULT_BACKLOG;
    ue_safe_alloc(clients.clients, uv_tcp_t *, DEFAULT_BACKLOG);
    for (i = 0; i < clients.max_clients; i++) {
        clients.clients[i] = NULL;
    }
    clients.clients_number = 0;

    if ((r = uv_listen((uv_stream_t*) &server, DEFAULT_BACKLOG, on_new_connection))) {
        ue_stacktrace_push_msg("Listen error: %s", uv_strerror(r));
        goto clean_up;
    }

    ue_logger_info("Before uv_run()");
    uv_run(loop, UV_RUN_DEFAULT);
    ue_logger_info("After uv_run()");

clean_up:
    if (clients.clients) {
        for (i = 0; i < clients.max_clients; i++) {
            if (clients.clients[i]) {
                free(clients.clients[i]);
            }
        }
        free(clients.clients);
    }
    uv_loop_delete(loop);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return EXIT_SUCCESS;
}
