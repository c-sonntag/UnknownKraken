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

#ifndef UnknownKrakenUtils_WARN_UNUSED_RESULT_H
#define UnknownKrakenUtils_WARN_UNUSED_RESULT_H

#include <uk/utils/compiler/bool.h>
#include <uk/utils/compiler/inline.h>

#if defined(__unix__)
    #include <sys/cdefs.h>
#endif

#if defined(__clang__)

#define uk_utils__warn_result __attribute__((__warn_unused_result__))

#elif defined(__GNUC__)

#define uk_utils__warn_result __attribute__((warn_unused_result))

#elif defined(_MSC_VER) && (_MSC_VER >= 1700)

#define uk_utils__warn_result _Check_return_

#else

#error (No warn_unused_result builtin found)

#endif

uk_utils__inline(bool) uk_utils__warn_result uk_utils__warn_unused_result(bool x) {
    return x;
}

#endif
