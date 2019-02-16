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

#ifndef UNKNOWNECHOUTILSMODULE_PRAGMA_H
#define UNKNOWNECHOUTILSMODULE_PRAGMA_H

/* Check if Microsoft Visual C++ compiler is used */
#if defined(_MSC_VER)

/**
 * @brief Disable a warning on win platform for MSC
 *           You must call UEUM_DISABLE_WIN32_PRAGMA_WARN_END afterwards.
 *
 * @source: https://stackoverflow.com/a/13577924
 */
#define UEUM_DISABLE_WIN32_PRAGMA_WARN(nnn) \
    __pragma (warning (push)) \
    __pragma (warning(disable : nnn)) \

#define UEUM_DISABLE_WIN32_PRAGMA_WARN_END() \
    __pragma (warning (pop)) \

/**
 * @brief Disable the warning https://docs.microsoft.com/fr-fr/cpp/error-messages/compiler-warnings/compiler-warning-level-1-c4047
 *           for MSC 
 */
#define UEUM_DISABLE_Wtype_limits() \
    UEUM_DISABLE_WIN32_PRAGMA_WARN(4047) \

#define UEUM_DISABLE_Wtype_limits_END() \
    UEUM_DISABLE_WIN32_PRAGMA_WARN_END() \

/* Check if GCC-like compiler is used */
#elif defined(__GNUC__)

#define UEUM_DISABLE_Wtype_limits() \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wtype-limits\"") \

#define UEUM_DISABLE_Wtype_limits_END() \
    _Pragma("GCC diagnostic pop") \

/* Set empty defines otherwise */
#else

#define UEUM_DISABLE_Wtype_limits()
#define UEUM_DISABLE_Wtype_limits_END()

#endif

#endif
