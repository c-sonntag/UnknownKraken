#ifndef UNKNOWNECHO_ZLIB_ERROR_HANDLING_H
#define UNKNOWNECHO_ZLIB_ERROR_HANDLING_H

#include <unknownecho/errorHandling/stacktrace.h>

void ue_zlib_error_handling_impl(int error_code);

#define ue_zlib_error_handling(error_code) ue_zlib_error_handling_impl(error_code);

#endif
