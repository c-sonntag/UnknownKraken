#ifndef UNKNOWNECHO_STRING_UTILITY_H
#define UNKNOWNECHO_STRING_UTILITY_H

#include <unknownecho/bool.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

void ue_remove_last_char(char *str);

bool ue_last_char_is(char *str, char c);

char *ue_strcat_variadic(const char *format, ...);

int ue_find_str_in_data(char *data, const char *query);

char *ue_get_file_name_from_path(char *path);

char *ue_get_file_extension(char *path);

char *ue_string_create_from(const char *str);

char *ue_string_create_from_bytes(unsigned char *bytes, size_t size);

char *ue_append_dump_string(char *data, size_t max);

bool ue_starts_with(const char *pre, const char *str);

int ue_last_index_of(const char *string, char target);

char *ue_string_reverse(char *string);

bool ue_int_to_string(int num, char *buffer, int radix);

bool ue_long_to_string(long num, char *buffer, int radix);

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
bool ue_string_to_int(char *string, int *out, int radix);

bool ue_string_to_long(char *string, long *out, int radix);

int ue_digit(char c, int radix);

/**
 * Returns a string that is a ue_substring of this string. The
 * ue_substring begins at the specified {@code begin_index} and
 * extends to the character at index {@code end_index - 1}.
 * Thus the length of the ue_substring is {@code end_index-begin_index}.
 *
 * Examples:
 * "hamburger".ue_substring(4, 8) returns "urge"
 * "smiles".ue_substring(1, 5) returns "mile"
 *
 * @param      begin_index   the beginning index, inclusive.
 * @param      end_index     the ending index, exclusive.
 * @return     the specified ue_substring.
 */
char *ue_substring(char *string, int begin_index, int end_index);

char *ue_get_until_symbol(char *str, int begin, char symbol, int *end);

char *ue_trim_whitespace(char *str);

#endif
