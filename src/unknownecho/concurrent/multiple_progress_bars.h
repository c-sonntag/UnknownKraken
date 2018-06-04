#ifndef UNKNOWNECHO_MULTIPLE_PROGRESS_BARS_H
#define UNKNOWNECHO_MULTIPLE_PROGRESS_BARS_H

#include <unknownecho/console/progress_bar.h>
#include <unknownecho/bool.h>

#include <uv.h>

typedef struct {
    double *sizes;
    ue_progress_bar **bars;
} ue_multiple_progress_bars_print_context;

typedef struct {
    double current_size;
    uv_async_t async;
    int size;
    int id;
    ue_multiple_progress_bars_print_context *pc;
    void *user_ctx;
    int tasks_number;
    bool use_progress_bars;
} ue_multiple_progress_bars_iteration;

typedef struct {
    uv_work_t req;
    ue_multiple_progress_bars_iteration ctx;
    void (*user_work_callback)(uv_work_t *req);
    void (*user_after_callback)(uv_work_t *req, int status);
} ue_multiple_progress_bars_task;

typedef struct {
    ue_multiple_progress_bars_task **tasks;
    int tasks_number;
    ue_multiple_progress_bars_print_context pc;
    uv_loop_t *loop;
    bool use_progress_bars;
} ue_multiple_progress_bars;

typedef struct {
    const char *description;
    int size;
    void (*user_work_callback)(uv_work_t *req);
    void (*user_after_callback)(uv_work_t *req, int status);
    void *user_ctx;
} ue_multiple_progress_bars_work;

ue_multiple_progress_bars *ue_multiple_progress_bars_create(uv_loop_t *loop, ue_multiple_progress_bars_work **works, int works_number);

void ue_multiple_progress_bars_destroy(ue_multiple_progress_bars *multiple_progress_bars);

void ue_multiple_progress_bars_enable_progress_bars(ue_multiple_progress_bars *multiple_progress_bars, bool enable);

void ue_multiple_progress_bars_run(ue_multiple_progress_bars *multiple_progress_bars);

ue_multiple_progress_bars_work *ue_multiple_progress_bars_work_create(const char *description, int size,
    void (*user_work_callback)(uv_work_t *req),
    void (*user_after_callback)(uv_work_t *req, int status), void *user_ctx);

void ue_multiple_progress_bars_work_destroy(ue_multiple_progress_bars_work *work);

void ue_multiple_progress_bars_iteration_update(ue_multiple_progress_bars_iteration *ctx);

#endif
