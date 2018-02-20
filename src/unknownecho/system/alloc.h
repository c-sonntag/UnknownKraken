#ifndef UNKNOWNECHO_ALLOC_H
#define UNKNOWNECHO_ALLOC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unknownecho/errorHandling/stacktrace.h>

/*
 * Alloc a variable in a safe way.
 * Set variable to NULL,
 * and alloc it to specified size and cast to specified type.
 * Set all elements to 0 with memset.
 * Check if variable is correctly allocated.
 */
#define ue_safe_alloc(var, type, size) \
	var = NULL; \
	var = (type*)malloc(size * sizeof(type)); \
	memset(var, 0, size * sizeof(type)); \
    ue_check_alloc(var) \

#define ue_safe_alloc_ret(var, type, size, ret) \
	var = NULL; \
	var = (type*)malloc(size * sizeof(type)); \
	memset(var, 0, size * sizeof(type)); \
    if (errno == ENOMEM) { \
        ue_stacktrace_push_errno() \
        ue_safe_free(var) \
        ret = 0; \
	} else if (!var) { \
        ue_stacktrace_push_msg("No such memory to allocate") \
		ret = 0; \
	} \
	ret = 1; \

/*
 * Alloc a variable in a safe way.
 * Set variable to NULL,
 * and alloc it to specified size and cast to specified type.
 * Set all elements to 0 with memset.
 * Check if variable is correctly allocated. If not, go to specified label
 */
#define ue_safe_alloc_or_goto(var, type, size, label) \
	var = NULL; \
	var = (type*)malloc(size * sizeof(type)); \
	memset(var, 0, size * sizeof(type)); \
    ue_check_alloc_or_goto(var, label) \

/*
 * Realloc a variable in a safe way.
 * If size has to be increase, we add specified more size.
 * If size has to be reduce, the parameter more_size has to be equal to 0.
 * Set all elements to 0 with memset.
 * Check if variable is correctly allocated.
 */
#define ue_safe_realloc(var, type, old_size, more_size) \
	var = (type*)realloc(var, (old_size + more_size + 1) * sizeof(type)); \
	memset(var + old_size, 0, (more_size + 1) * sizeof(type)); \
    ue_check_alloc(var) \

/*
 * Realloc a variable in a safe way.
 * If size has to be increase, we add specified more size.
 * If size has to be reduce, the parameter more_size has to be equal to 0.
 * Set all elements to 0 with memset.
 * Check if variable is correctly allocated. If not, go to specified label
 */
#define ue_safe_realloc_or_goto(var, type, old_size, more_size, label) \
	var = (type*)realloc(var, (old_size + more_size + 1) * sizeof(type)); \
	memset(var + old_size, 0, (more_size + 1) * sizeof(type)); \
    ue_check_alloc_or_goto(var, label) \

/*
 * Check if a variable is correctly allocated.
 * Check if 'errno' variable is equal to value ENOMEM ;
 * if it is, we add an error message to ue_stacktrace.
 * Some OS didn't update 'errno' variable in this case, so we check
 * also if the variable is set to NULL ; if it is, we add an error
 * message to ue_stacktrace.
 */
#define ue_check_alloc(var) \
	if (errno == ENOMEM) { \
        ue_stacktrace_push_errno() \
        ue_safe_free(var) \
        return 0; \
	} else if (!var) { \
        ue_stacktrace_push_msg("No such memory to allocate") \
		return 0; \
	} \

/*
 * Same behavior than CHECK_ALLOC, but if var isn't
 * correctly allocated, go to specified label.
 */
#define ue_check_alloc_or_goto(var, label) \
	if (errno == ENOMEM) { \
        ue_stacktrace_push_errno() \
        ue_safe_free(var) \
        goto label; \
	} else if (!var) { \
        ue_stacktrace_push_msg("No such memory to allocate") \
		goto label; \
	} \

/*
 * Free a variable in a safe way.
 * Check if variable isn't set to NULL ;
 * if it is, free the variable and set it to NULL.
 */
#define ue_safe_free(var) \
	if (var) { \
		free((void*)var); \
		var = NULL; \
	} \

#define ue_safe_str_free(str) \
	if (str) { \
		if (strcmp(str, "") != 0) { \
			free((void *)str); \
			str = NULL; \
		} \
	} \

/*
 * Close a file in a safe way.
 * Check if the file descriptor isn't set to NULL ;
 * if it is, close the file descriptor and set it to NULL.
 */
#define ue_safe_fclose(fd) \
	if (fd) { \
		fclose(fd); \
		fd = NULL; \
	} \

#endif
