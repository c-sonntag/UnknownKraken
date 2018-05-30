#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <unknownecho/init.h>
#include <unknownecho/time/sleep.h>
#include <unknownecho/alloc.h>
#include <unknownecho/bool.h>
#include <unknownecho/concurrent/threadpool.h>

#include <uv.h>

void fake_download(uv_work_t *req) {
    ue_threadpool_iteration *ctx = req->data;
    int current_size = 0;
    while (current_size < ctx->size) {
        ctx->current_size = current_size;
        uv_async_send(&ctx->async);
        ue_millisleep(100);
        current_size += (200 + random()) % 1000;
    }
}

void after(uv_work_t *req, int status) {
    ue_threadpool_iteration *ctx = req->data;

    ctx->current_size = ctx->size;

    ue_threadpool_iteration_update(ctx);

    uv_close((uv_handle_t*) &ctx->async, NULL);
}

ue_threadpool_work **create_threadpool_work(int n) {
    ue_threadpool_work **work;
    int i;

    ue_safe_alloc(work, ue_threadpool_work *, n);

    for (i = 0; i < n; i++) {
        work[i] = ue_threadpool_work_create("Downloading", 10240, fake_download, after, NULL);
    }

    return work;
}

void destroy_threadpool_work(ue_threadpool_work **work, int n) {
    int i;

    for (i = 0; i < n; i++) {
        ue_threadpool_work_destroy(work[i]);
    }

    ue_safe_free(work);
}

int main() {
    uv_loop_t *loop;
    ue_threadpool *threadpool;
    ue_threadpool_work **work;
    int n;

    ue_init();

    loop = uv_default_loop();
    n = 5;

    setenv("UV_THREADPOOL_SIZE", "32", 1);

    work = create_threadpool_work(n);

    threadpool = ue_threadpool_create(loop, work, n);

    ue_threadpool_run(threadpool);

    uv_run(loop, UV_RUN_DEFAULT);

    destroy_threadpool_work(work, n);

    ue_threadpool_destroy(threadpool);

    uv_loop_delete(loop);

    ue_uninit();

    return 0;
}
