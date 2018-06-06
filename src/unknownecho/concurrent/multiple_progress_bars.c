#include <unknownecho/concurrent/multiple_progress_bars.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/console/console.h>
#include <unknownecho/alloc.h>

#include <stdio.h>

/**
 * @todo add error handling
 */

static void print_progress(uv_async_t *handle) {
    ue_multiple_progress_bars_iteration *ctx = handle->data;

    ue_multiple_progress_bars_iteration_update(ctx);
}

ue_multiple_progress_bars *ue_multiple_progress_bars_create(uv_loop_t *loop, ue_multiple_progress_bars_work **works, int works_number) {
    ue_multiple_progress_bars *multiple_progress_bars;
    int i;

    ue_safe_alloc(multiple_progress_bars, ue_multiple_progress_bars, 1);

    ue_safe_alloc(multiple_progress_bars->pc.bars, ue_progress_bar *, works_number);

    ue_safe_alloc(multiple_progress_bars->tasks, ue_multiple_progress_bars_task *, works_number);
    multiple_progress_bars->tasks_number = works_number;

    ue_safe_alloc(multiple_progress_bars->pc.sizes, double, works_number);

    for (i = 0; i < works_number; i++) {
        ue_safe_alloc(multiple_progress_bars->tasks[i], ue_multiple_progress_bars_task, 1);
        multiple_progress_bars->tasks[i]->ctx.size = works[i]->size;
        multiple_progress_bars->tasks[i]->ctx.current_size = 0.0;
        multiple_progress_bars->tasks[i]->ctx.id = i;
        multiple_progress_bars->tasks[i]->user_work_callback = works[i]->user_work_callback;
        multiple_progress_bars->tasks[i]->user_after_callback = works[i]->user_after_callback;
        multiple_progress_bars->tasks[i]->ctx.user_ctx = works[i]->user_ctx;
        multiple_progress_bars->tasks[i]->ctx.tasks_number = works_number;
        multiple_progress_bars->loop = loop;
        multiple_progress_bars->pc.sizes[i] = 0.0;
        multiple_progress_bars->pc.bars[i] = ue_progress_bar_create(works[i]->size, works[i]->description, stdout);
        ue_progress_bar_set_style(multiple_progress_bars->pc.bars[i], "#", "-");
        ue_progress_bar_set_left_delimiter(multiple_progress_bars->pc.bars[i], "|");
        ue_progress_bar_set_right_delimiter(multiple_progress_bars->pc.bars[i], "|");
        ue_progress_bar_use_return_chariot(multiple_progress_bars->pc.bars[i], false);
        multiple_progress_bars->tasks[i]->ctx.pc = &multiple_progress_bars->pc;
        multiple_progress_bars->tasks[i]->req.data = (void *) &multiple_progress_bars->tasks[i]->ctx;
        uv_async_init(loop, &multiple_progress_bars->tasks[i]->ctx.async, print_progress);
        multiple_progress_bars->tasks[i]->ctx.async.data = &multiple_progress_bars->tasks[i]->ctx;
        multiple_progress_bars->use_progress_bars = true;
        multiple_progress_bars->tasks[i]->ctx.use_progress_bars = true;
    }

    return multiple_progress_bars;
}

void ue_multiple_progress_bars_destroy(ue_multiple_progress_bars *multiple_progress_bars) {
    int i;

    ue_safe_free(multiple_progress_bars->pc.sizes);

    for (i = 0; i < multiple_progress_bars->tasks_number; i++) {
        ue_progress_bar_destroy(multiple_progress_bars->pc.bars[i]);
    }
    ue_safe_free(multiple_progress_bars->pc.bars);

    for (i = 0; i < multiple_progress_bars->tasks_number; i++) {
        ue_safe_free(multiple_progress_bars->tasks[i]);
    }
    ue_safe_free(multiple_progress_bars->tasks);

    ue_safe_free(multiple_progress_bars);
}

void ue_multiple_progress_bars_enable_progress_bars(ue_multiple_progress_bars *multiple_progress_bars, bool enable) {
    int i;

    multiple_progress_bars->use_progress_bars = enable;

    for (i = 0; i < multiple_progress_bars->tasks_number; i++) {
        multiple_progress_bars->tasks[i]->ctx.use_progress_bars = enable;
    }
}

void ue_multiple_progress_bars_run(ue_multiple_progress_bars *multiple_progress_bars) {
    int i;

    for (i = 0; i < multiple_progress_bars->tasks_number; i++) {
        uv_queue_work(multiple_progress_bars->loop, &multiple_progress_bars->tasks[i]->req, multiple_progress_bars->tasks[i]->user_work_callback,
            multiple_progress_bars->tasks[i]->user_after_callback);
    }
}

ue_multiple_progress_bars_work *ue_multiple_progress_bars_work_create(const char *description, int size,
    void (*user_work_callback)(uv_work_t *req),
    void (*user_after_callback)(uv_work_t *req, int status), void *user_ctx) {

    ue_multiple_progress_bars_work *work;

    ue_safe_alloc(work, ue_multiple_progress_bars_work, 1);
    work->description = ue_string_create_from(description);
    work->size = size;
    work->user_work_callback = user_work_callback;
    work->user_after_callback = user_after_callback;
    work->user_ctx = user_ctx;

    return work;
}

void ue_multiple_progress_bars_work_destroy(ue_multiple_progress_bars_work *work) {
    ue_safe_free(work->description);
    ue_safe_free(work);
}

void ue_multiple_progress_bars_iteration_update(ue_multiple_progress_bars_iteration *ctx) {
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
