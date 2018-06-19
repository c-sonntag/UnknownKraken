/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/string/string_utility.h>
#include <uecm/string/string_builder.h>
#include <ei/ei.h>
#include <uecm/alloc.h>

#include <string.h>
#include <stdarg.h>
#include <ctype.h> /* for isspace(), toupper() */
#include <errno.h>
#include <limits.h>
#include <stdint.h>

void uecm_remove_last_char(char *str) {
	if (!str) {
		return;
	}

	str[strlen(str) - 1] = '\0';
}

bool uecm_last_char_is(char *str, char c) {
	return (!str || str[strlen(str) - 1] != c) ? false : true;
}

char *uecm_strcat_variadic(const char *format, ...) {
	uecm_string_builder *s;
	va_list ap;
	size_t i;
	char c, *src, *concatenated;
	int d;
	double f;
    int64_t L;
	long int l;
	unsigned int u;

	ei_check_parameter_or_return(format);

	src = NULL;
	concatenated = NULL;

	for (i = 0; i < strlen(format); i++) {
		if (format[i] != 's' && format[i] != 'd' && format[i] != 'L' &&
			format[i] != 'l' && format[i] != 'f' && format[i] != 'c' &&
			format[i] != 'u') {
			ei_stacktrace_push_msg(
					"Specified format isn't valid. It must be contains only characters 's', 'd', 'L', 'l', 'f', 'c' and 'u'");
			return NULL;
		}
	}

	if ((s = uecm_string_builder_create()) == NULL) {
		ei_stacktrace_push_msg("Failed to create empty string builder");
		return NULL;
	}

	va_start(ap, format);
	while (*format) {
		switch (*format++) {
		case 's':
			src = va_arg(ap, char *);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			break;

		case 'd':
			d = va_arg(ap, int);
			uecm_safe_alloc(src, char, 10);
			sprintf(src, "%d", d);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;

		case 'L':
			L = va_arg(ap, long long int);
			uecm_safe_alloc(src, char, 20);
#if defined(_WIN32) || defined(_WIN64)
#if defined(__GNUC__)
            _Pragma("GCC diagnostic push")
            _Pragma("GCC diagnostic ignored \"-Wformat\"")
#endif
                sprintf(src, "%I64d", L);
#if defined(__GNUC__)
            _Pragma("GCC diagnostic pop")
#endif
#else
            sprintf(src, "%lld", L);
#endif
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;

		case 'l':
			l = va_arg(ap, long int);
			uecm_safe_alloc(src, char, 20);
			sprintf(src, "%ld", l);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;

		case 'f':
			f = va_arg(ap, double);
			uecm_safe_alloc(src, char, 10);
			sprintf(src, "%f", f);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;

		case 'c':
			c = (char) va_arg(ap, int);
			uecm_safe_alloc(src, char, 2);
			sprintf(src, "%c", c);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;

		case 'u':
			u = va_arg(ap, unsigned int);
			uecm_safe_alloc(src, char, 10);
			sprintf(src, "%u", u);
			if (!uecm_string_builder_append(s, src, strlen(src))) {
				break;
			}
			free((void*) src);
			break;
		}
	}

	va_end(ap);

	if (s->data) {
		uecm_safe_alloc(concatenated, char, strlen(s->data) + 1);
		memcpy(concatenated, s->data, (strlen(s->data) + 1) * sizeof(char));
	}

	uecm_string_builder_destroy(s);

	return concatenated;
}

int uecm_find_str_in_data(char *data, const char *query) {
	char *tmp_data;
	int data_size, query_len, position;

	tmp_data = data;
	data_size = (int)strlen(data);
	query_len = (int)strlen(query);
	position = 0;

	while (1) {
		if (tmp_data + data_size - tmp_data < query_len) {
			break;
		}
		if (*tmp_data == query[0]) {
			if (memcmp(tmp_data, query, query_len) == 0) {
				return position;
			}
		}
		tmp_data++;
		position++;
	}

	return -1;
}

char *uecm_get_file_name_from_path(char *path) {
	char *file_name, *tmp_file_name;

	if (!strstr(path, "/")) {
		uecm_safe_alloc(file_name, char, strlen(path) + 1);
		strcpy(file_name, path);
		return file_name;
	}

	tmp_file_name = strrchr(path, '/');
	uecm_safe_alloc(file_name, char, strlen(tmp_file_name + 1) + 1);
	strcpy(file_name, tmp_file_name + 1);

	return file_name;
}

char *uecm_get_file_extension(char *path) {
	char *file_name, *tmp_file_name;

	if (!strstr(path, ".")) {
		uecm_safe_alloc(file_name, char, strlen(path) + 1);
		strcpy(file_name, path);
		return file_name;
	}

	tmp_file_name = strrchr(path, '.');
	uecm_safe_alloc(file_name, char, strlen(tmp_file_name + 1) + 1);
	strcpy(file_name, tmp_file_name + 1);

	return file_name;
}

char *uecm_string_create_from(const char *str) {
	char *new_str;

	uecm_safe_alloc(new_str, char, strlen(str) + 1);
	strcpy(new_str, str);

	return new_str;
}

char *uecm_string_create_from_bytes(unsigned char *bytes, size_t size) {
	char *string;

	uecm_safe_alloc(string, char, size + 1);
	memcpy(string, bytes, size * sizeof(char));

	return string;
}

char *uecm_append_dump_string(char *data, size_t max) {
	char *dump;

	if (max <= strlen(data)) {
		return uecm_string_create_from(data);
	}

	uecm_safe_alloc(dump, char, max + 1);
	strcpy(dump, data);
	memset(dump + strlen(data), ' ', (max - strlen(data)) * sizeof(char));

	return dump;
}

bool uecm_starts_with(const char *pre, const char *str) {
	size_t lenpre = strlen(pre), lenstr = strlen(str);
	return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

int uecm_last_index_of(const char *string, char target) {
	int r;
	int current_index;

	r = -1;
	current_index = 0;

	while (string[current_index] != '\0') {
		if (string[current_index] == target) {
			r = current_index;
		}

		current_index++;
	}

	return r;
}

char *uecm_string_reverse(char *string) {
	char c;
	char *s0, *s1;

	s0 = string - 1;
	s1 = string;

	/* Find the end of the string */
	while (*s1) {
		++s1;
	}

	/* Reverse it */
	while (s1-- > ++s0) {
		c = *s0;
		*s0 = *s1;
		*s1 = c;
	}

	return string;
}

bool uecm_int_to_string(int num, char *buffer, int radix) {
	int i, remainder;
	bool is_negative;

	i = 0;
	is_negative = false;

	/* Handle 0 explicitely, otherwise empty string is printed for 0 */
	if (num == 0) {
		buffer[i++] = '0';
		buffer[i] = '\0';
		return false;
	}

	/**
	 * In standard itoa(), negative numbers are handled only with
	 * radix 10. Otherwise numbers are considered unsigned.
	 */
	if (num < 0 && radix == 10) {
		is_negative = true;
		num = -num;
	}

	/* Process individual digits */
	while (num != 0) {
		remainder = num % radix;
		buffer[i++] =
				(char)((remainder > 9) ? (remainder - 10) + 'a' : remainder + '0');
		num = num / radix;
	}

	/* If number is negative, append '-' */
	if (is_negative) {
		buffer[i++] = '-';
	}

	/* Append string terminator */
	buffer[i] = '\0';

	buffer = uecm_string_reverse(buffer);

	return true;
}

bool uecm_long_to_string(long num, char *buffer, int radix) {
	int i, remainder;
	bool is_negative;

	i = 0;
	is_negative = false;

	/* Handle 0 explicitely, otherwise empty string is printed for 0 */
	if (num == 0) {
		buffer[i++] = '0';
		buffer[i] = '\0';
		return false;
	}

	/**
	 * In standard itoa(), negative numbers are handled only with
	 * radix 10. Otherwise numbers are considered unsigned.
	 */
	if (num < 0 && radix == 10) {
		is_negative = true;
		num = -num;
	}

	/* Process individual digits */
	while (num != 0) {
		remainder = num % radix;
		buffer[i++] =
				(char)((remainder > 9) ? (remainder - 10) + 'a' : remainder + '0');
		num = num / radix;
	}

	/* If number is negative, append '-' */
	if (is_negative) {
		buffer[i++] = '-';
	}

	/* Append string terminator */
	buffer[i] = '\0';

	buffer = uecm_string_reverse(buffer);

	return true;
}

bool uecm_string_to_int(char *string, int *out, int radix) {
	char *end;
	long l;

	ei_check_parameter_or_return(string);

	if (string[0] == '\0' || isspace((unsigned char ) string[0])) {
		ei_stacktrace_push_msg("String is incovertible");
		return false;
	}

	errno = 0;
	l = strtol(string, &end, radix);

	/* Both checks are needed because INT_MAX == LONG_MAX is possible. */
	if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX)) {
		ei_stacktrace_push_msg("String overflow");
		return false;
	}
	if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN)) {
		ei_stacktrace_push_msg("String underflow");
		return false;
	}
	if (*end != '\0') {
		ei_stacktrace_push_msg("String is incovertible");
		return false;
	}

	*out = l;

	return true;
}

bool uecm_string_to_long(char *string, long *out, int radix) {
	char *end;
	long l;

	ei_check_parameter_or_return(string);

	if (string[0] == '\0' || isspace((unsigned char ) string[0])) {
		ei_stacktrace_push_msg("String is incovertible");
		return false;
	}

	errno = 0;
	l = strtol(string, &end, radix);

	/* Both checks are needed because INT_MAX == LONG_MAX is possible. */
	if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX)) {
		ei_stacktrace_push_msg("String overflow");
		return false;
	}
	if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN)) {
		ei_stacktrace_push_msg("String underflow");
		return false;
	}
	if (*end != '\0') {
		ei_stacktrace_push_msg("String is incovertible");
		return false;
	}

	*out = l;

	return true;
}

int uecm_digit(char c, int radix) {
	char *string, *error_message;
	int number;

	number = 0;

	uecm_safe_alloc(string, char, 2);
	string[0] = c;
	if (!uecm_string_to_int(string, &number, radix)) {
		error_message = uecm_strcat_variadic("scsds", "Failed to convert char `", c,
				"` to radix `", radix, "`");
		ei_stacktrace_push_msg(error_message);
		uecm_safe_str_free(error_message);
	}

	uecm_safe_str_free(string);

	return number;
}

char *uecm_substring(char *string, int begin_index, int end_index) {
	int sub_length;
	char *new_string;

	if (begin_index < 0) {
		ei_stacktrace_push_msg("Index out of bounds");
		return NULL;
	}

	if (end_index > strlen(string)) {
		ei_stacktrace_push_msg("Index out of bounds");
		return NULL;
	}

	sub_length = end_index - begin_index;
	if (sub_length < 0) {
		ei_stacktrace_push_msg("Index out of bounds exception");
		return NULL;
	}

	if ((begin_index == 0) && (end_index == strlen(string))) {
		return uecm_string_create_from(string);
	}

	uecm_safe_alloc(new_string, char, strlen(string) + 1);
	strncpy(new_string, string + begin_index, sub_length);
	return new_string;
}

char *uecm_get_until_symbol(char *str, int begin, char symbol, int *end) {
	char *line;
	int i, cr, line_size;
	size_t size;

	line = NULL;
	cr = -1;
	size = strlen(str);
	*end = -1;

	for (i = begin; i < size; i++) {
		if (str[i] == symbol) {
			cr = i;
			break;
		}
	}

	if (cr != -1) {
		line_size = cr - begin;
		uecm_safe_alloc(line, char, line_size + 1);
		memcpy(line, str + begin, line_size * sizeof(char));
	}

	*end = cr;

	return line;
}

char *uecm_trim_whitespace(char *str) {
	char *end;

	while (isspace((unsigned char )*str)) {
		str++;
	}

	 /* All spaces? */
	if (*str == 0) {
		return str;
	}

	/* Trim trailing space */
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char )*end)) {
		end--;
	}

	/* Write new null terminator */
	*(end + 1) = 0;

	return str;
}

char *uecm_string_uppercase(const char *input) {
	char *output;
	size_t length, i;

	ei_check_parameter_or_return(input);

	length = strlen(input);

	uecm_safe_alloc(output, char, length);

	for (i = 0; i < length; i++) {
		output[i] = (char)toupper(input[i]);
	}

	return output;
}
