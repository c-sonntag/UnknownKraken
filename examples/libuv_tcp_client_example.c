#include <uv.h>

#include <stdlib.h>

/*void on_connect(uv_connect_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "connect failed error %s\n", uv_err_name(status));
        free(req);
        return;
    }

    uv_read_start((uv_stream_t*) req->handle, alloc_buffer, on_read);
    uv_write()
    free(req);
}*/

int main() {
    /*uv_loop_t *loop;

    loop = uv_default_loop();

    uv_connect_t *connect_req = (uv_connect_t*) malloc(sizeof(uv_connect_t));
    uv_tcp_t *socket = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, socket);

    uv_tcp_connect(connect_req, socket, (const struct sockaddr*) res->ai_addr, on_connect);

    return uv_run(loop, UV_RUN_DEFAULT);*/

    return 0;
}
