#ifndef UNKNOWNECHO_LOGGER_MANAGER_H
#define UNKNOWNECHO_LOGGER_MANAGER_H

#include <unknownecho/bool.h>
#include <unknownecho/errorHandling/logger_struct.h>
#include <unknownecho/errorHandling/logger.h>

bool ue_logger_manager_init();

void ue_logger_manager_uninit();

ue_logger *ue_logger_manager_get_logger();

#endif
