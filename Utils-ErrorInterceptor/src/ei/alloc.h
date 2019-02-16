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
 * @file      alloc.h
 * @brief     Macro functions to safely alloc/realloc/free variables.
 * @author    Charly Lamothe
 * @copyright Apache License 2.0.
 */

#ifndef LIBERRORINTERCEPTOR_ALLOC_H
#define LIBERRORINTERCEPTOR_ALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

/*********************************************************************
 *                             API    functions                      *
 *********************************************************************/

/**
 * @brief Alloc a variable in a safe way.
 * 
 * @param  ptr  pointer variable to allocate.
 * @param  type type of the variable.
 * @param  size number of item of type `type` to allocate in `ptr`.
 * @pre    Ensure that `ptr` is set to NULL before.
 * @return On success, `ptr` is allocated. Otherwise, 0 is returned.
 * @code
 * char *ptr = NULL;
 * ei_safe_alloc(ptr, char, 10);
 * @endcode
 */
#define ei_safe_alloc(ptr, type, size) \
    __ei_safe_alloc_internal(ptr, type, size, return 0); \

#define ei_safe_alloc_ret(ptr, type, size, ret) \
    __ei_safe_alloc_internal(ptr, type, size, ret = 0); \
    ret = 1; \

/**
 * @brief Alloc a variable in a safe way.
 */
#define ei_safe_alloc_or_goto(ptr, type, size, label) \
    __ei_safe_alloc_internal(ptr, type, size, goto label); \

/**
 * @brief Realloc a variable in a safe way.
 *
 *  If size has to be increase, we add specified more size.
 *  If size has to be reduce, the parameter more_size has to be equal to 0.
 *  Set all elements to 0 with memset.
 *  Check if variable is correctly allocated.
 */
#define ei_safe_realloc(ptr, type, old_size, more_size) \
    __ei_safe_realloc_internal(ptr, type, old_size, more_size, return 0); \

#define ei_safe_realloc_ret(ptr, type, old_size, more_size, ret) \
    __ei_safe_realloc_internal(ptr, type, old_size, more_size, ret = 0); \
    ret = 1; \

/**
 * @brief Realloc a variable in a safe way.
 *
 *  If size has to be increase, we add specified more size.
 *  If size has to be reduce, the parameter more_size has to be equal to 0.
 *  Set all elements to 0 with memset.
 *  Check if variable is correctly allocated. If not, go to specified label
 */
#define ei_safe_realloc_or_goto(ptr, type, old_size, more_size, label) \
    __ei_safe_realloc_internal(ptr, type, old_size, more_size, goto label); \

/**
 * @brief Free a variable in a safe way.
 *
 *  Check if variable isn't set to NULL ;
 *  if it is, free the variable and set it to NULL.
 */
#define ei_safe_free(ptr) \
    if (ptr) { \
        free((void *)ptr); \
        ptr = NULL; \
    } \

#define ei_safe_str_free(str) \
    if (str) { \
        if (strcmp(str, "") != 0) { \
            free((void *)str); \
            str = NULL; \
        } \
    } \

/**
 * @brief Close a file in a safe way.
 *
 *  Check if the file descriptor isn't set to NULL ;
 *  if it is, close the file descriptor and set it to NULL.
 */
#define ei_safe_fclose(fd) \
    if (fd) { \
        fclose(fd); \
        fd = NULL; \
    } \

/*********************************************************************
 *                         Other usefull functions                   *
 *********************************************************************/

/* Check if Microsoft Visual C++ compiler is used */
#if defined(_MSC_VER)

/**
 * @brief Disable a warning on win platform for MSC
 *           You must call EI_DISABLE_WIN32_PRAGMA_WARN_END afterwards.
 *
 * @source: https://stackoverflow.com/a/13577924
 */
#define EI_DISABLE_WIN32_PRAGMA_WARN(nnn) \
    __pragma (warning (push)) \
    __pragma (warning(disable : nnn)) \

#define EI_DISABLE_WIN32_PRAGMA_WARN_END() \
    __pragma (warning (pop)) \

/**
 * @brief Disable the warning https://docs.microsoft.com/fr-fr/cpp/error-messages/compiler-warnings/compiler-warning-level-1-c4047
 *           for MSC 
 */
#define EI_DISABLE_Wtype_limits() \
    EI_DISABLE_WIN32_PRAGMA_WARN(4047) \

#define EI_DISABLE_Wtype_limits_END() \
    EI_DISABLE_WIN32_PRAGMA_WARN_END() \

/* Check if GCC-like compiler is used */
#elif defined(__GNUC__)

#define EI_DISABLE_Wtype_limits() \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wtype-limits\"") \

#define EI_DISABLE_Wtype_limits_END() \
    _Pragma("GCC diagnostic pop") \

/* Set empty defines otherwise */
#else

#define EI_DISABLE_Wtype_limits()
#define EI_DISABLE_Wtype_limits_END()

#endif

/**
 * @brief Check if a variable is unsigned.
 *
 * @param a  must be an assigned variable or we enter in the undefined behavior area.
 * @return 1 if a is unsigned, 0 otherwise
 * @source inspired from https://stackoverflow.com/a/7470062
 * @note For an unsigned variable in parameter, some compilers warns a >= is always true (obviously).
 *       To prevent that, just set EI_DISABLE_Wtype_limits() before the call of EI_ISUNSIGNED() and
 *          EI_DISABLE_Wtype_limits_END() after the call of EI_ISUNSIGNED(). This will remove temporarily
 *       Wtype-limits from GCC and 4047 from MSC.
 */
#define EI_ISUNSIGNED(a) (sizeof(a) == sizeof(unsigned char)) || (a >= 0 && ~a >= 0)

/**
 * @brief Get the max value of a variable, by resolving its type.
 * 
 * @param ptr  must be an assigned variable or we enter in the undefined behavior area.
 * @source inspired from https://stackoverflow.com/a/12769452
 */
#define EI_VAR_MAX(ptr)                                         \
(                                                               \
    !EI_ISUNSIGNED(ptr) ?                                       \
        ((1ll << (sizeof(ptr) * CHAR_BIT - 2)) - 1 +            \
         (1ll << (sizeof(ptr) * CHAR_BIT - 2))) :                \
        (                                                       \
              (sizeof(ptr) < sizeof(long long)) ?                 \
            ((1ll << (sizeof(ptr) * CHAR_BIT - 1)) - 1 +        \
             (1ll << (sizeof(ptr) * CHAR_BIT - 1))) :            \
            (                                                   \
                  (sizeof(ptr) == sizeof(long long)) ?            \
                -1ll :                                          \
                (fprintf(stderr, "%s\n",                        \
                "[LIBEI] [FATAL] [ALLOCATION] [EI_VAR_MAX()]"   \
                "Unsuported type"),                             \
                 exit(EXIT_FAILURE),                                \
                 0)                                              \
            )                                                   \
        )                                                       \
)

/**
 * @brief Get the min value of a variable, by resolving its type.
 * 
 * @param ptr  must be an assigned variable or we enter in the undefined behavior area.
 * @source inspired from https://stackoverflow.com/a/12769452
 */
#define EI_VAR_MIN(ptr)                                 \
(                                                      \
    !EI_ISUNSIGNED(ptr) ?                              \
        (-((1ll << (sizeof(ptr) * CHAR_BIT - 2)) - 1 + \
        (1ll << (sizeof(ptr) * CHAR_BIT - 2))) - 1) :  \
        0                                              \
)

/**
 * @brief Cross-plateform includes to resolve the function used by the current
 *           OS to get the number of bytes allocated by a specified ptr. See below.
 * 
 * @source inspired from file lzham_mem.cpp from project lzham_codec_devel:
 *            https://github.com/richgel999/lzham_codec_devel/blob/master/lzhamdecomp/lzham_mem.cpp
 */
#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
#elif defined(__APPLE__)
    #include <malloc/malloc.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
    #include <malloc_np.h>
#else
    #include <malloc.h>
#endif
    
/**
 * @brief Cross-plateform macro to get the number of bytes
 *        allocated by ptr in the HEAP.
 * 
 * @source inspired from this old commit, in file lzham_mem.cpp from project lzham_codec:
 *            https://github.com/fearog/lzham_codec/blob/75089234ebfa58dcf6631865acd2297b1b604df6/lzhamdecomp/lzham_mem.cpp
 */
#if defined(_WIN32) || defined(_WIN64)
    #define ei_get_allocation_size(ptr) _msize(ptr)
#elif !defined(__APPLE__) && !defined(ANDROID)
    #define ei_get_allocation_size(ptr) malloc_usable_size(ptr)
#else
    #define ei_get_allocation_size(ptr) malloc_size(ptr)
#endif

/*********************************************************************
 *                             Internal functions                            *
 *********************************************************************/

#define __ei_check_not_already_assigned_or_rollback(ptr, rollback_expression) \
    if (ptr != NULL) { \
        fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_check_not_already_assigned_or_rollback()] ptr isn't NULL\n"); \
        rollback_expression; \
    } \

#define __ei_check_allocated_or_rollback(ptr, rollback_expression) \
    if (ptr == NULL) { \
        fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_check_allocated_or_rollback()] Cannot reallocate a NULL ptr\n"); \
        rollback_expression; \
    } \

#define __ei_check_allocation_size_or_rollback(ptr, requested_size, rollback_expression) \
    if (ei_get_allocation_size(ptr) < (size_t)requested_size) { \
        fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_check_allocation_size_or_rollback()] malloc() doesn't allocated enough memory\n"); \
        free((void *)ptr); \
        rollback_expression; \
    } \

#define __ei_check_size_not_null_or_rollback(size, rollback_expression) \
    if (size == 0) { \
        fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_check_size_not_null_or_rollback()] Cannot allocate 0 byte\n"); \
        rollback_expression; \
    } \

#define __ei_check_size_not_max_or_rollback(size, rollback_expression) \
    EI_DISABLE_Wtype_limits() \
    if (size == EI_VAR_MAX(size)) { \
    EI_DISABLE_Wtype_limits_END() \
        fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_check_size_not_max_or_rollback()] Cannot allocate with size equal to the max of the specified size type\n"); \
        rollback_expression; \
    } \

#define __ei_try_malloc_or_rollback(ptr, type, size, rollback_expression) \
    errno = 0; \
    if ((ptr = (type *)malloc(size * sizeof(type))) == NULL) { \
        if (errno != 0) { \
            fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_try_malloc_or_rollback()] malloc() failed with error message: %s\n", strerror(errno)); \
        } else { \
            fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_try_malloc_or_rollback()] malloc() failed without setting errno\n"); \
        } \
        rollback_expression; \
    } \

#define __ei_try_realloc_or_rollback(ptr, type, old_size, more_size, rollback_expression) \
    errno = 0; \
    if ((ptr = (type *)realloc(ptr, (old_size + more_size + 1) * sizeof(type))) == NULL) { \
        if (errno != 0) { \
            fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_try_realloc_or_rollback()] realloc() failed with error message: %s\n", strerror(errno)); \
        } else { \
            fprintf(stderr, "[LIBEI] [ERROR] [ALLOCATION] [__ei_try_realloc_or_rollback()] realloc() failed without setting errno\n"); \
        } \
        rollback_expression; \
    } \

#define __ei_safe_alloc_internal(ptr, type, size, rollback_expression) \
    __ei_check_not_already_assigned_or_rollback(ptr, rollback_expression); \
    __ei_check_size_not_null_or_rollback(size, rollback_expression); \
    __ei_check_size_not_max_or_rollback(size, rollback_expression); \
    __ei_try_malloc_or_rollback(ptr, type, size, rollback_expression); \
    __ei_check_allocation_size_or_rollback(ptr, size, rollback_expression); \
    memset(ptr, 0, size * sizeof(type)); \

#define __ei_safe_realloc_internal(ptr, type, old_size, more_size, rollback_expression) \
    __ei_check_allocated_or_rollback(ptr, rollback_expression); \
    __ei_check_size_not_null_or_rollback(old_size, rollback_expression); \
    __ei_check_size_not_null_or_rollback(more_size, rollback_expression); \
    __ei_check_size_not_max_or_rollback(old_size, rollback_expression); \
    __ei_check_size_not_max_or_rollback(more_size, rollback_expression); \
    __ei_try_realloc_or_rollback(ptr, type, old_size, more_size, rollback_expression); \
    __ei_check_allocation_size_or_rollback(ptr, (old_size + more_size + 1) * sizeof(type), rollback_expression); \
    memset(ptr + old_size, 0, (more_size + 1) * sizeof(type)); \

#endif
