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
 *  @file      bool.h
 *  @brief     Portable way to represent bool type.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef ERRORINTERCEPTOR_BOOL_H
#define ERRORINTERCEPTOR_BOOL_H

#if !defined(__cplusplus)

 /* C99 */
#if __STDC_VERSION__ >= 199901L

#include <stdbool.h>

#elif defined(_MSC_VER)

#define bool _Bool
#define true 1
#define false 0
#define __bool_true_false_are_defined 1

#else /* Not C99 */

typedef enum {
    false,
    true
} bool;

#endif

#endif

#endif /* BOOL_H */
