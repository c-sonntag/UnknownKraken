/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoUtilsModule.                             *
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

#ifndef UnknownKrakenUtils_SAFE_ARITHMETIC_H
#define UnknownKrakenUtils_SAFE_ARITHMETIC_H

#include <uk/utils/compiler/overflow.h>
#include <uk/utils/compiler/typename.h>

#include <uk/utils/ei.h>

#define uk_utils_safe_add(a, b, res) \
    uk___utils_safe_add_internal(a, b, res, return 0); \

#define uk_utils_safe_add_or_goto(a, b, res, label) \
    uk___utils_safe_add_internal(a, b, res, goto label); \

#define uk_utils_safe_add3(a, b, c, res) \
    uk___utils_safe_add3_internal(a, b, c, res, return 0); \

#define uk_utils_safe_add3_or_goto(a, b, c, res, label) \
    uk___utils_safe_add3_internal(a, b, c, res, goto label); \

#define uk_utils_safe_sub(a, b, res) \
    uk___utils_safe_sub_internal(a, b, res, return 0); \

#define uk_utils_safe_sub_or_goto(a, b, res, label) \
    uk___utils_safe_sub_internal(a, b, res, goto label); \

#define uk_utils_safe_mul(a, b, res) \
    uk___utils_safe_mul_internal(a, b, res, return 0); \

#define uk_utils_safe_mul_or_goto(a, b, res, label) \
    uk___utils_safe_mul_internal(a, b, res, goto label); \

#define uk___utils_safe_add_internal(a, b, res, rollback_expression) \
    if (uk_utils__add_overflow(a, b, res)) { \
        uk_utils_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)+(%s)", uk_utils_typename(res), \
            uk_utils_typename(a), uk_utils_typename(b)); \
        rollback_expression; \
    } \

#define uk___utils_safe_add3_internal(a, b, c, res, rollback_expression) \
    if (uk_utils__add3_overflow(a, b, c, res)) { \
        uk_utils_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)+(%s)+(%s)", uk_utils_typename(res), \
            uk_utils_typename(a), uk_utils_typename(b), uk_utils_typename(c)); \
        rollback_expression; \
    } \

#define uk___utils_safe_sub_internal(a, b, res, rollback_expression) \
    if (uk_utils__sub_overflow(a, b, res)) { \
        uk_utils_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)-(%s)", uk_utils_typename(res), \
            uk_utils_typename(a), uk_utils_typename(b)); \
        rollback_expression; \
    } \

#define uk___utils_safe_mul_internal(a, b, res, rollback_expression) \
    if (uk_utils__mul_overflow(a, b, res)) { \
        uk_utils_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)*(%s)", uk_utils_typename(res), \
            uk_utils_typename(a), uk_utils_typename(b)); \
        rollback_expression; \
    } \

#endif
