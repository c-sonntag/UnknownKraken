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
 *  @brief     Provides macro to record UnknownKrakenUtils_INVALID_PARAMETER error code
 *             and return if specified parameter is null.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UnknownKrakenUtils_CHECK_PARAMETER_H
#define UnknownKrakenUtils_CHECK_PARAMETER_H

#include <uk/utils/stacktrace/stacktrace.h>
#include <uk/utils/error/error.h>

#define uk_utils_unused(x) (void)(x);

#define uk_utils_check_parameter(p) \
    if (!(p)) { \
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER) \
        return; \
    } \

#define uk_utils_check_parameter_or_return(p) \
    if (!(p)) { \
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER) \
        return 0; \
    } \

#define uk_utils_check_parameter_or_goto(p, label) \
    if (!(p)) { \
        uk_utils_stacktrace_push_code(UnknownKrakenUtils_INVALID_PARAMETER) \
        goto label; \
    } \

#endif /* CHECK_PARAMETER_H */
