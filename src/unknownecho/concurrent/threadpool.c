#include <unknownecho/concurrent/threadpool.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/console/console.h>
#include <unknownecho/alloc.h>

#include <stdio.h>

static void print_progress(uv_async_t *handle) {
    ue_threadpool_iteration *ctx = handle->data;

    ue_threadpool_iteration_update(ctx);
}

ue_threadpool *ue_threadpool_create(uv_loop_t *loop, ue_threadpool_work **works, int works_number) {
    ue_threadpool *threadpool;
    int i;

    ue_safe_alloc(threadpool, ue_threadpool, 1);

    ue_safe_alloc(threadpool->pc.bars, ue_progress_bar *, works_number);

    ue_safe_alloc(threadpool->tasks, ue_threadpool_task *, works_number);
    threadpool->tasks_number = works_number;

    ue_safe_alloc(threadpool->pc.sizes, double, works_number);

    for (i = 0; i < works_number; i++) {
        ue_safe_alloc(threadpool->tasks[i], ue_threadpool_task, 1);
        threadpool->tasks[i]->ctx.size = works[i]->size;
        threadpool->tasks[i]->ctx.current_size = 0.0;
        threadpool->tasks[i]->ctx.id = i;
        threadpool->tasks[i]->user_work_callback = works[i]->user_work_callback;
        threadpool->tasks[i]->user_after_callback = works[i]->user_after_callback;
        threadpool->tasks[i]->ctx.user_ctx = works[i]->user_ctx;
        threadpool->tasks[i]->ctx.tasks_number = works_number;
        threadpool->loop = loop;
        threadpool->pc.sizes[i] = 0.0;
        threadpool->pc.bars[i] = ue_progress_bar_create(works[i]->size, works[i]->description, stdout);
        ue_progress_bar_set_style(threadpool->pc.bars[i], "#", "-");
        ue_progress_bar_set_left_delimiter(threadpool->pc.bars[i], "|");
        ue_progress_bar_set_right_delimiter(threadpool->pc.bars[i], "|");
        ue_progress_bar_use_return_chariot(threadpool->pc.bars[i], false);
        threadpool->tasks[i]->ctx.pc = &threadpool->pc;
        threadpool->tasks[i]->req.data = (void *) &threadpool->tasks[i]->ctx;
        uv_async_init(loop, &threadpool->tasks[i]->ctx.async, print_progress);
        threadpool->tasks[i]->ctx.async.data = &threadpool->tasks[i]->ctx;
        threadpool->use_progress_bars = true;
        threadpool->tasks[i]->ctx.use_progress_bars = true;
    }

    return threadpool;
}

void ue_threadpool_destroy(ue_threadpool *threadpool) {
    int i;

    ue_safe_free(threadpool->pc.sizes);

    for (i = 0; i < threadpool->tasks_number; i++) {
        ue_progress_bar_destroy(threadpool->pc.bars[i]);
    }
    ue_safe_free(threadpool->pc.bars);

    for (i = 0; i < threadpool->tasks_number; i++) {
        ue_safe_free(threadpool->tasks[i]);
    }
    ue_safe_free(threadpool->tasks);

    ue_safe_free(threadpool);
}

void ue_threadpool_enable_progress_bars(ue_threadpool *threadpool, bool enable) {
    int i;

    threadpool->use_progress_bars = enable;

    for (i = 0; i < threadpool->tasks_number; i++) {
        threadpool->tasks[i]->ctx.use_progress_bars = enable;
    }
}

void ue_threadpool_run(ue_threadpool *threadpool) {
    int i;

    for (i = 0; i < threadpool->tasks_number; i++) {
        uv_queue_work(threadpool->loop, &threadpool->tasks[i]->req, threadpool->tasks[i]->user_work_callback,
            threadpool->tasks[i]->user_after_callback);
    }
}

ue_threadpool_work *ue_threadpool_work_create(const char *description, int size,
    void (*user_work_callback)(uv_work_t *req),
    void (*user_after_callback)(uv_work_t *req, int status), void *user_ctx) {

    ue_threadpool_work *work;

    ue_safe_alloc(work, ue_threadpool_work, 1);
    work->description = ue_string_create_from(description);
    work->size = size;
    work->user_work_callback = user_work_callback;
    work->user_after_callback = user_after_callback;
    work->user_ctx = user_ctx;

    return work;
}

void ue_threadpool_work_destroy(ue_threadpool_work *work) {
    ue_safe_free(work->description);
    ue_safe_free(work);
}

void ue_threadpool_iteration_update(ue_threadpool_iteration *ctx) {
    int i;

    ctx->pc->sizes[ctx->id] = ctx->current_size;
    ue_progress_bar_update(ctx->pc->bars[ctx->id], ctx->pc->sizes[ctx->id]);

    if (ctx->use_progress_bars) {
        ue_console_erase_previous_lines(ctx->tasks_number);
        for (i = 0; i < ctx->tasks_number; i++) {
            ue_progress_bar_print(ctx->pc->bars[i]);
        }
    }
}
