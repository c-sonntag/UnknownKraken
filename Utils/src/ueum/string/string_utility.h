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

#ifndef UNKNOWNECHOUTILSMODULE_STRING_UTILITY_H
#define UNKNOWNECHOUTILSMODULE_STRING_UTILITY_H

#include <ueum/compiler/bool.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

void ueum_remove_last_char(char *str);

bool ueum_last_char_is(const char *str, char c);

char *ueum_strcat_variadic(const char *format, ...);

int ueum_find_str_in_data(char *data, const char *query);

char *ueum_get_file_name_from_path(char *path);

char *ueum_get_file_extension(char *path);

char *ueum_string_create_from(const char *str);

char *ueum_string_create_from_bytes(unsigned char *bytes, size_t size);

char *ueum_append_dump_string(char *data, size_t max);

bool ueum_starts_with(const char *pre, const char *str);

int ueum_last_index_of(const char *string, char target);

char *ueum_string_reverse(char *string);

bool ueum_int_to_string(int num, char *buffer, int radix);

bool ueum_long_to_string(long num, char *buffer, int radix);

/**
 * Convert char * string to int out.
 * @param[in] string Input string to be converted.
 *
 * The format is the same as strtol,
 * except that the following are inconvertible:
 * - empty string
 * - leading whitespace
 * - any trailing characters that are not part of the number
 *   cannot be NULL.
 *
 * @param[out] out The converted int. Cannot be NULL.
 * @param[in] radix Base to interpret string in. Same range as strtol (2 to 36).
 * @return Indicates if the operation succeeded, or why it failed.
 */
bool ueum_string_to_int(char *string, int *out, int radix);

bool ueum_string_to_long(char *string, long *out, int radix);

/**
 * Returns a string that is a ueum_substring of this string. The
 * ueum_substring begins at the specified {@code begin_index} and
 * extends to the character at index {@code end_index - 1}.
 * Thus the length of the ueum_substring is {@code end_index-begin_index}.
 *
 * Examples:
 * ueum_substring("hamburger", 4, 8) returns "urge"
 * ueum_substring("smiles", 1, 5) returns "mile"
 *
 * @param      begin_index   the beginning index, inclusive.
 * @param      end_index     the ending index, exclusive.
 * @return     the specified ueum_substring.
 */
char *ueum_substring(char *string, size_t begin_index, size_t end_index);

char *ueum_get_until_symbol(char *str, int begin, char symbol, int *end);

char *ueum_trim_whitespace(char *str);

char *ueum_string_uppercase(const char *input);

#endif
