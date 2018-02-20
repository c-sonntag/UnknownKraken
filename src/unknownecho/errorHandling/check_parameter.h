#ifndef CHECK_PARAMETER_H
#define CHECK_PARAMETER_H

#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/error.h>

#define ue_unused(x) (void)(x);

#define ue_check_parameter(p) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        return; \
    } \

#define ue_check_parameter_or_return(p) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        return 0; \
    } \

#define ue_check_parameter_or_goto(p, label) \
    if (!(p)) { \
        ue_stacktrace_push_code(UNKNOWNECHO_INVALID_PARAMETER) \
        goto label; \
    } \

#endif /* CHECK_PARAMETER_H */
