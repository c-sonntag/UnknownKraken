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

#ifndef UNKNOWNECHOUTILSMODULE_SAFE_ARITHMETIC_H
#define UNKNOWNECHOUTILSMODULE_SAFE_ARITHMETIC_H

#include <ueum/compiler/overflow.h>
#include <ueum/compiler/typename.h>

#include <ei/ei.h>

#define ueum_safe_add(a, b, res) \
    __ueum_safe_add_internal(a, b, res, return 0); \

#define ueum_safe_add_or_goto(a, b, res, label) \
    __ueum_safe_add_internal(a, b, res, goto label); \

#define ueum_safe_add3(a, b, c, res) \
    __ueum_safe_add3_internal(a, b, c, res, return 0); \

#define ueum_safe_add3_or_goto(a, b, c, res, label) \
    __ueum_safe_add3_internal(a, b, c, res, goto label); \

#define ueum_safe_sub(a, b, res) \
    __ueum_safe_sub_internal(a, b, res, return 0); \

#define ueum_safe_sub_or_goto(a, b, res, label) \
    __ueum_safe_sub_internal(a, b, res, goto label); \

#define ueum_safe_mul(a, b, res) \
    __ueum_safe_mul_internal(a, b, res, return 0); \

#define ueum_safe_mul_or_goto(a, b, res, label) \
    __ueum_safe_mul_internal(a, b, res, goto label); \

#define __ueum_safe_add_internal(a, b, res, rollback_expression) \
    if (ueum__add_overflow(a, b, res)) { \
        ei_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)+(%s)", ueum_typename(res), \
            ueum_typename(a), ueum_typename(b)); \
        rollback_expression; \
    } \

#define __ueum_safe_add3_internal(a, b, c, res, rollback_expression) \
    if (ueum__add3_overflow(a, b, c, res)) { \
        ei_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)+(%s)+(%s)", ueum_typename(res), \
            ueum_typename(a), ueum_typename(b), ueum_typename(c)); \
        rollback_expression; \
    } \

#define __ueum_safe_sub_internal(a, b, res, rollback_expression) \
    if (ueum__sub_overflow(a, b, res)) { \
        ei_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)-(%s)", ueum_typename(res), \
            ueum_typename(a), ueum_typename(b)); \
        rollback_expression; \
    } \

#define __ueum_safe_mul_internal(a, b, res, rollback_expression) \
    if (ueum__mul_overflow(a, b, res)) { \
        ei_stacktrace_push_msg("Arithmetic overflow detected when performing: (%s)=(%s)*(%s)", ueum_typename(res), \
            ueum_typename(a), ueum_typename(b)); \
        rollback_expression; \
    } \

#endif
