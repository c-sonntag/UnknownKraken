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

#ifndef UnknownKrakenUtils_PRAGMA_H
#define UnknownKrakenUtils_PRAGMA_H

/* Check if Microsoft Visual C++ compiler is used */
#if defined(_MSC_VER)

/**
 * @brief Disable a warning on win platform for MSC
 *           You must call UK_UTILS_DISABLE_WIN32_PRAGMA_WARN_END afterwards.
 *
 * @source: https://stackoverflow.com/a/13577924
 */
#define UK_UTILS_DISABLE_WIN32_PRAGMA_WARN(nnn) \
    __pragma (warning (push)) \
    __pragma (warning(disable : nnn))

#define UK_UTILS_DISABLE_WIN32_PRAGMA_WARN_END() \
    __pragma (warning (pop))

/**
 * @brief Disable the warning https://docs.microsoft.com/fr-fr/cpp/error-messages/compiler-warnings/compiler-warning-level-1-c4047
 *           for MSC 
 */
#define UK_UTILS_DISABLE_Wtype_limits() \
    UK_UTILS_DISABLE_WIN32_PRAGMA_WARN(4047) \

#define UK_UTILS_DISABLE_Wtype_limits_END() \
    UK_UTILS_DISABLE_WIN32_PRAGMA_WARN_END() \

/* Check if GCC-like compiler is used */
#elif defined(__GNUC__)

#define UK_UTILS_DISABLE_Wtype_limits() \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wtype-limits\"") \

#define UK_UTILS_DISABLE_Wtype_limits_END() \
    _Pragma("GCC diagnostic pop") \

/* Set empty defines otherwise */
#else

#define UK_UTILS_DISABLE_Wtype_limits()
#define UK_UTILS_DISABLE_Wtype_limits_END()

#endif

#endif
