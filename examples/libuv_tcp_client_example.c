#include <unknownecho/init.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/console/input.h>

#include <uv.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void on_connect(uv_connect_t *req, int status);
void on_write(uv_write_t *req, int status);

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    /* @todo check returned value */
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t *) req;
    ue_safe_free(wr->buf.base);
    ue_safe_free(wr);
}

void on_write(uv_write_t *req, int status) {
    if (status) {
        ue_stacktrace_push_msg("Write error: %s", uv_strerror(status));
        return;
    }
    ue_logger_info("Wrote\n");
    free_write_req(req);
}

void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    ssize_t i;

    if (nread >= 0) {
        printf(" ! %s\n", buf->base );
        for (i = 0; i < nread; i++) {
            printf("%c", buf->base[i]);
        }
        printf("\n");
    }
    else {
        uv_close((uv_handle_t *)client, NULL);
    }

    free(buf->base);
}

void producer(uv_work_t *req) {
    char *input;
    //uv_stream_t *stream;

    /* @todo add error handling */
    //cl_ctx->write_req = (write_req_t *)malloc(sizeof(write_req_t));

    while (true) {
        if (!(input = ue_input_string(">"))) {
            ue_logger_error("Invalid input");
            continue;
        }

        //ue_logger_debug("input: %s", input);

        if (strcmp(input, "-q") == 0) {
            //uv_close((uv_handle_t *)stream, NULL);
            break;
        }

        //cl_ctx->write_req->buf = uv_buf_init(input, strlen(input));
        //uv_write((uv_write_t *)req, stream, &cl_ctx->write_req->buf, 1, on_write);

        //uv_async_send(&ctx->async);
    }
}

void consumer(uv_work_t *req) {
    //uv_stream_t *stream;

    //stream = cl_ctx->stream;

    while (true) {
        /* @todo add error handling for this three functions */

        //uv_read_start(stream, alloc_cb, on_read);

    }
}

/**
 * see that: https://luka.strizic.info/post/libuv-standard-input/output-and-TCP-input/output-example/
 */
void on_connect(uv_connect_t *connection, int status) {
    if (status) {
        ue_stacktrace_push_msg("Connect error: %s", uv_strerror(status));
        return;
    }

    ue_logger_info("Connected");


}

void on_walk(uv_handle_t *handle, void *arg) {
    if (handle) {
        uv_close(handle, NULL);
    }
}

void on_sigint_received(uv_signal_t *handle, int signum) {
    printf("Signal received: %d\n", signum);
    if (uv_loop_close(handle->loop) == UV_EBUSY) {
        uv_walk(handle->loop, on_walk, NULL);
    }
}


int main(int argc, char **argv) {
    uv_loop_t *loop;
    struct sockaddr_in addr;
    uv_signal_t sigint;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize LibUnknownEcho\n");
        exit(EXIT_FAILURE);
    }

    loop = uv_default_loop();

    setenv("UV_THREADPOOL_SIZE", "32", 1);

    /* @todo add error handling */
    uv_signal_init(loop, &sigint);

    /* @todo add error handling */
    uv_signal_start(&sigint, on_sigint_received, SIGINT);

    uv_tcp_t socket;
    uv_tcp_init(loop, &socket);
    uv_tcp_keepalive(&socket, 1, 60);

    uv_ip4_addr("0.0.0.0", 7000, &addr);

    uv_connect_t connect;
    uv_tcp_connect(&connect, &socket, (const struct sockaddr *) &addr, on_connect);

    uv_run(loop, UV_RUN_DEFAULT);

//clean_up:
    uv_loop_delete(loop);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return EXIT_SUCCESS;
}
