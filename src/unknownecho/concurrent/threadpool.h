#ifndef UNKNOWNECHO_THREADPOOL_H
#define UNKNOWNECHO_THREADPOOL_H

#include <unknownecho/console/progress_bar.h>
#include <unknownecho/bool.h>

#include <uv.h>

typedef struct {
    double *sizes;
    ue_progress_bar **bars;
} ue_threadpool_print_context;

typedef struct {
    double current_size;
    uv_async_t async;
    int size;
    int id;
    ue_threadpool_print_context *pc;
    void *user_ctx;
    int tasks_number;
    bool use_progress_bars;
} ue_threadpool_iteration;

typedef struct {
    uv_work_t req;
    ue_threadpool_iteration ctx;
    void (*user_work_callback)(uv_work_t *req);
    void (*user_after_callback)(uv_work_t *req, int status);
} ue_threadpool_task;

typedef struct {
    ue_threadpool_task **tasks;
    int tasks_number;
    ue_threadpool_print_context pc;
    uv_loop_t *loop;
    bool use_progress_bars;
} ue_threadpool;

typedef struct {
    const char *description;
    int size;
    void (*user_work_callback)(uv_work_t *req);
    void (*user_after_callback)(uv_work_t *req, int status);
    void *user_ctx;
} ue_threadpool_work;

ue_threadpool *ue_threadpool_create(uv_loop_t *loop, ue_threadpool_work **works, int works_number);

void ue_threadpool_destroy(ue_threadpool *threadpool);

void ue_threadpool_enable_progress_bars(ue_threadpool *threadpool, bool enable);

void ue_threadpool_run(ue_threadpool *threadpool);

ue_threadpool_work *ue_threadpool_work_create(const char *description, int size,
    void (*user_work_callback)(uv_work_t *req),
    void (*user_after_callback)(uv_work_t *req, int status), void *user_ctx);

void ue_threadpool_work_destroy(ue_threadpool_work *work);

void ue_threadpool_iteration_update(ue_threadpool_iteration *ctx);

#endif
