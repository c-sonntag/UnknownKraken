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

#ifndef UNKNOWNECHOUTILSMODULE_TYPECHECK_H
#define UNKNOWNECHOUTILSMODULE_TYPECHECK_H

#ifndef typecheck

#include <ueum/compiler/typeof.h>

#if __STDC_VERSION__ >= 201112L

/* Compile-time assertion that check if 'x' and 'y' are equivalent types */
#define typecheck(x, y) do { \
    _Static_assert(__builtin_types_compatible_p(__typeof__(x),__typeof__(y)), \
        "Arithmetic overflow detected: incompatible types"); \
} while (0)

#else

/*
 * SPDX-License-Identifier: GPL-2.0
 * 
 * from https://github.com/torvalds/linux/blob/master/include/linux/typecheck.h
 * 
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type, x) \
({    type __dummy; \
    __typeof__(x) __dummy2; \
    (void)(&__dummy == &__dummy2); \
    1; \
})

#endif

#endif

#endif
