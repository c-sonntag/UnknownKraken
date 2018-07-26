/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibErrorInterceptor.                                   *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

/**
 *  @file      check_parameter.h
 *  @brief     Provides macro to record ERRORINTERCEPTOR_INVALID_PARAMETER error code
 *             and return if specified parameter is null.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef ERRORINTERCEPTOR_CHECK_PARAMETER_H
#define ERRORINTERCEPTOR_CHECK_PARAMETER_H

#include <ei/stacktrace/stacktrace.h>
#include <ei/error/error.h>

#define ei_unused(x) (void)(x);

#define ei_check_parameter(p) \
    if (!(p)) { \
        ei_stacktrace_push_code(ERRORINTERCEPTOR_INVALID_PARAMETER) \
        return; \
    } \

#define ei_check_parameter_or_return(p) \
    if (!(p)) { \
        ei_stacktrace_push_code(ERRORINTERCEPTOR_INVALID_PARAMETER) \
        return 0; \
    } \

#define ei_check_parameter_or_goto(p, label) \
    if (!(p)) { \
        ei_stacktrace_push_code(ERRORINTERCEPTOR_INVALID_PARAMETER) \
        goto label; \
    } \

#endif /* CHECK_PARAMETER_H */
