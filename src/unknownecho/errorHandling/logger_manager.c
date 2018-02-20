#include <unknownecho/errorHandling/logger_manager.h>

static ue_logger *log = NULL;

bool ue_logger_manager_init() {
    log = ue_logger_create();
    ue_logger_set_details(log, false);
    return true;
}

void ue_logger_manager_uninit() {
    ue_logger_destroy(log);
}

ue_logger *ue_logger_manager_get_logger() {
    return log;
}
