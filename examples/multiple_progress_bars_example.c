#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <unknownecho/init.h>
#include <unknownecho/time/sleep.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/concurrent/multiple_progress_bars.h>

#include <uv.h>

void fake_download(uv_work_t *req) {
    ue_multiple_progress_bars_iteration *ctx = req->data;
    int current_size = 0;
    while (current_size < ctx->size) {
        ctx->current_size = current_size;
        uv_async_send(&ctx->async);
        ue_millisleep(100);
        current_size += (200 + random()) % 1000;
    }
}

/**
 * @todo check error from status
 */
void after(uv_work_t *req, int status) {
    ue_multiple_progress_bars_iteration *ctx = req->data;

    ctx->current_size = ctx->size;

    ue_multiple_progress_bars_iteration_update(ctx);

    uv_close((uv_handle_t*) &ctx->async, NULL);
}

ue_multiple_progress_bars_work **create_multiple_progress_bars_work(int n) {
    ue_multiple_progress_bars_work **work;
    int i;

    ue_safe_alloc(work, ue_multiple_progress_bars_work *, n);

    for (i = 0; i < n; i++) {
        work[i] = ue_multiple_progress_bars_work_create("Downloading", 10240, fake_download, after, NULL);
    }

    return work;
}

void destroy_multiple_progress_bars_work(ue_multiple_progress_bars_work **work, int n) {
    int i;

    for (i = 0; i < n; i++) {
        ue_multiple_progress_bars_work_destroy(work[i]);
    }

    ue_safe_free(work);
}

int main(int argc, char **argv) {
    uv_loop_t *loop;
    ue_multiple_progress_bars *multiple_progress_bars;
    ue_multiple_progress_bars_work **work;
    int n;

    ue_init();

    if (argc == 2) {
        n = atoi(argv[1]);
    } else {
        n = 5;
    }

    loop = uv_default_loop();

    setenv("UV_THREADPOOL_SIZE", "32", 1);

    work = create_multiple_progress_bars_work(n);

    multiple_progress_bars = ue_multiple_progress_bars_create(loop, work, n);

    ue_multiple_progress_bars_run(multiple_progress_bars);

    uv_run(loop, UV_RUN_DEFAULT);

    destroy_multiple_progress_bars_work(work, n);

    ue_multiple_progress_bars_destroy(multiple_progress_bars);

    uv_loop_delete(loop);

    ue_uninit();

    return 0;
}
