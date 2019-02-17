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

#ifndef UnknownKrakenUtils_SAFE_ALLOC_H
#define UnknownKrakenUtils_SAFE_ALLOC_H

#include <uk/utils/compiler/pragma.h>
#include <uk/utils/compiler/likely.h>

#include <uk/utils/ei.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/*********************************************************************
 *                             API functions                         *
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
 * uk_utils_safe_alloc(ptr, char, 10);
 * @endcode
 */
#define uk_utils_safe_alloc(ptr, type, size) \
    uk___utils_safe_alloc_internal(ptr, type, size, return 0); \

#define uk_utils_safe_alloc_ret(ptr, type, size, ret) \
    uk___utils_safe_alloc_internal(ptr, type, size, ret = 0); \
    ret = 1; \

/**
 * @brief Alloc a variable in a safe way.
 */
#define uk_utils_safe_alloc_or_goto(ptr, type, size, label) \
    uk___utils_safe_alloc_internal(ptr, type, size, goto label); \

/**
 * @brief Realloc a variable in a safe way.
 *
 *  If size has to be increase, we add specified more size.
 *  If size has to be reduce, the parameter more_size has to be equal to 0.
 *  Set all elements to 0 with memset.
 *  Check if variable is correctly allocated.
 */
#define uk_utils_safe_realloc(ptr, type, old_size, more_size) \
    uk___utils_safe_realloc_internal(ptr, type, old_size, more_size, return 0); \

#define uk_utils_safe_realloc_ret(ptr, type, old_size, more_size, ret) \
    uk___utils_safe_realloc_internal(ptr, type, old_size, more_size, ret = 0); \
    ret = 1; \

/**
 * @brief Realloc a variable in a safe way.
 *
 *  If size has to be increase, we add specified more size.
 *  If size has to be reduce, the parameter more_size has to be equal to 0.
 *  Set all elements to 0 with memset.
 *  Check if variable is correctly allocated. If not, go to specified label
 */
#define uk_utils_safe_realloc_or_goto(ptr, type, old_size, more_size, label) \
    uk___utils_safe_realloc_internal(ptr, type, old_size, more_size, goto label); \

/**
 * @brief Free a variable in a safe way.
 *
 *  Check if variable isn't set to NULL ;
 *  if it is, free the variable and set it to NULL.
 */
#define uk_utils_safe_free(ptr) \
    if (ptr) { \
        free((void *)ptr); \
        ptr = NULL; \
    } \

#define uk_utils_safe_str_free(str) \
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
#define uk_utils_safe_fclose(fd) \
    if (fd) { \
        fclose(fd); \
        fd = NULL; \
    } \

/*********************************************************************
 *                         Other usefull functions                   *
 *********************************************************************/

/**
 * @brief Check if a variable is unsigned.
 *
 * @param a  must be an assigned variable or we enter in the undefined behavior area.
 * @return 1 if a is unsigned, 0 otherwise
 * @source inspired from https://stackoverflow.com/a/7470062
 * @note For an unsigned variable in parameter, some compilers warns a >= is always true (obviously).
 *       To prevent that, just set UK_UTILS_DISABLE_Wtype_limits() before the call of UK_UTILS_ISUNSIGNED() and
 *          UK_UTILS_DISABLE_Wtype_limits_END() after the call of UK_UTILS_ISUNSIGNED(). This will remove temporarily
 *       Wtype-limits from GCC and 4047 from MSC.
 */
#define UK_UTILS_ISUNSIGNED(a) (sizeof(a) == sizeof(unsigned char)) || (a >= 0 && ~a >= 0)

/**
 * @brief Get the max value of a variable, by resolving its type.
 * 
 * @param ptr  must be an assigned variable or we enter in the undefined behavior area.
 * @source inspired from https://stackoverflow.com/a/12769452
 */
#define UK_UTILS_VAR_MAX(ptr)                                     \
(                                                             \
    !UK_UTILS_ISUNSIGNED(ptr) ?                                   \
        ((1ll << (sizeof(ptr) * CHAR_BIT - 2)) - 1 +          \
         (1ll << (sizeof(ptr) * CHAR_BIT - 2))) :             \
         (                                                    \
            (sizeof(ptr) < sizeof(long long)) ?               \
             ((1ll << (sizeof(ptr) * CHAR_BIT - 1)) - 1 +     \
             (1ll << (sizeof(ptr) * CHAR_BIT - 1))) :         \
            (                                                 \
                  (sizeof(ptr) == sizeof(long long)) ?        \
                -1ll :                                        \
                (fprintf(stderr, "[FATAL] Unsupported type"), \
                 exit(EXIT_FAILURE),                          \
                 0)                                           \
            )                                                 \
         )                                                    \
)

/**
 * @brief Get the min value of a variable, by resolving its type.
 * 
 * @param ptr  must be an assigned variable or we enter in the undefined behavior area.
 * @source inspired from https://stackoverflow.com/a/12769452
 */
#define UK_UTILS_VAR_MIN(ptr)                              \
(                                                      \
    !UK_UTILS_ISUNSIGNED(ptr) ?                            \
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
 *         https://github.com/fearog/lzham_codec/blob/75089234ebfa58dcf6631865acd2297b1b604df6/lzhamdecomp/lzham_mem.cpp
 */
#if defined(_WIN32) || defined(_WIN64)
    #define uk_utils_get_allocation_size(ptr) _msize(ptr)
#elif !defined(__APPLE__) && !defined(ANDROID)
    #define uk_utils_get_allocation_size(ptr) malloc_usable_size(ptr)
#else
    #define uk_utils_get_allocation_size(ptr) malloc_size(ptr)
#endif

/*********************************************************************
 *                             Internal functions                    *
 *********************************************************************/

#define uk___utils_check_not_already_assigned_or_rollback(ptr, rollback_expression) \
    if (ptr != NULL) { \
        uk_utils_stacktrace_push_msg("ptr isn't NULL"); \
        rollback_expression; \
    } \

#define uk___utils_check_allocated_or_rollback(ptr, rollback_expression) \
    if (ptr == NULL) { \
        uk_utils_stacktrace_push_msg("Cannot reallocate a NULL ptr"); \
        rollback_expression; \
    } \

#define uk___utils_check_allocation_size_or_rollback(ptr, requested_size, rollback_expression) \
    if (uk_utils_get_allocation_size(ptr) < (size_t)requested_size) { \
        uk_utils_stacktrace_push_msg("malloc() doesn't allocated enough memory"); \
        free((void *)ptr); \
        rollback_expression; \
    } \

#define uk___utils_check_size_not_null_or_rollback(size, rollback_expression) \
    if (size == 0) { \
        uk_utils_stacktrace_push_msg("Cannot allocate 0 byte"); \
        rollback_expression; \
    } \

#define uk___utils_check_size_not_max_or_rollback(size, rollback_expression) \
    UK_UTILS_DISABLE_Wtype_limits() \
    if (size == UK_UTILS_VAR_MAX(size)) { \
    UK_UTILS_DISABLE_Wtype_limits_END() \
        uk_utils_stacktrace_push_msg("Cannot allocate with size equal to the max of the specified size type"); \
        rollback_expression; \
    } \

#define uk___utils_try_malloc_or_rollback(ptr, type, size, rollback_expression) \
    errno = 0; \
    if (unlikely((ptr = (type *)malloc(size * sizeof(type))) == NULL)) { \
        if (errno != 0) { \
            uk_utils_stacktrace_push_msg("malloc() failed with error message: %s", strerror(errno)); \
        } else { \
            uk_utils_stacktrace_push_msg("malloc() failed without setting errno"); \
        } \
        rollback_expression; \
    } \

#define uk___utils_try_realloc_or_rollback(ptr, type, old_size, more_size, rollback_expression) \
    errno = 0; \
    if (unlikely((ptr = (type *)realloc(ptr, (old_size + more_size + 1) * sizeof(type))) == NULL)) { \
        if (errno != 0) { \
            uk_utils_stacktrace_push_msg("realloc() failed with error message: %s", strerror(errno)); \
        } else { \
            uk_utils_stacktrace_push_msg("realloc() failed without setting errno"); \
        } \
        rollback_expression; \
    } \

#define uk___utils_safe_alloc_internal(ptr, type, size, rollback_expression) \
    uk___utils_check_not_already_assigned_or_rollback(ptr, rollback_expression); \
    uk___utils_check_size_not_null_or_rollback(size, rollback_expression); \
    uk___utils_check_size_not_max_or_rollback(size, rollback_expression); \
    uk___utils_try_malloc_or_rollback(ptr, type, size, rollback_expression); \
    uk___utils_check_allocation_size_or_rollback(ptr, size, rollback_expression); \
    memset(ptr, 0, size * sizeof(type)); \

#define uk___utils_safe_realloc_internal(ptr, type, old_size, more_size, rollback_expression) \
    uk___utils_check_allocated_or_rollback(ptr, rollback_expression); \
    uk___utils_check_size_not_null_or_rollback(old_size, rollback_expression); \
    uk___utils_check_size_not_null_or_rollback(more_size, rollback_expression); \
    uk___utils_check_size_not_max_or_rollback(old_size, rollback_expression); \
    uk___utils_check_size_not_max_or_rollback(more_size, rollback_expression); \
    uk___utils_try_realloc_or_rollback(ptr, type, old_size, more_size, rollback_expression); \
    uk___utils_check_allocation_size_or_rollback(ptr, (old_size + more_size + 1) * sizeof(type), rollback_expression); \
    memset(ptr + old_size, 0, (more_size + 1) * sizeof(type)); \

#endif
