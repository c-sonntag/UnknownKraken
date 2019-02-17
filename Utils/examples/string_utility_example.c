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

#include <uk/utils/ueum.h>
#include <uk/utils/ei.h>

#include <stdio.h>

int main() {
    char *hello, *path, *file_name, *file_extension,
        *string_number, *substring, *string_part, *whitespaces,
        *uppercased;
    int number, symbol_pos;

    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    hello = NULL;
    path = NULL;
    file_name = NULL;
    file_extension = NULL;
    string_number = NULL;
    substring = NULL;
    string_part = NULL;
    whitespaces = NULL;
    uppercased = NULL;
    
    uk_utils_logger_info("Creating string hello...");
    if ((hello = uk_utils_string_create_from("Hello world !")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create string hello");
        goto clean_up;
    }
    uk_utils_logger_info("Original content of string hello is: %s\n", hello);

    uk_utils_logger_info("Creating string path...");
    if ((path = uk_utils_string_create_from("/usr/include/uk/utils/ueum.h")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create string path");
        goto clean_up;
    }
    uk_utils_logger_info("Original content of string path is: %s\n", path);

    uk_utils_logger_info("Creating string string_number...");
    if ((string_number = uk_utils_string_create_from("42")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create string string_number");
        goto clean_up;
    }
    uk_utils_logger_info("Original content of string string_number is: %s\n", string_number);

    uk_utils_logger_info("Creating string whitespaces...");
    if ((whitespaces = uk_utils_string_create_from("123   ")) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to create string whitespaces");
        goto clean_up;
    }
    uk_utils_logger_info("Original content of string whitespaces is: %s\n", whitespaces);

    uk_utils_logger_info("Removing the last char of string hello...");
    uk_utils_remove_last_char(hello);
    uk_utils_logger_info("The content of string hello is now: %s\n", hello);

    uk_utils_logger_info("Verifiying that the last char of the modified string is a space...");
    if (!uk_utils_last_char_is(hello, ' ')) {
        uk_utils_stacktrace_push_msg("The last char isn't a space");
        goto clean_up;
    }
    uk_utils_logger_info("OK\n");

    uk_utils_logger_info("The position of string 'world' is at index: %d\n", uk_utils_find_str_in_data(hello, "world"));

    uk_utils_logger_info("Extracting the file name from string path...");
    if ((file_name = uk_utils_get_file_name_from_path(path)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract file name from string path");
        goto clean_up;
    }
    uk_utils_logger_info("The file name of the path is: %s\n", file_name);

    uk_utils_logger_info("Extracting the file extension from string file_name...");
    if ((file_extension = uk_utils_get_file_extension(file_name)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to get file extension from string file_name");
        goto clean_up;
    }
    uk_utils_logger_info("The file extension of the file is: %s\n", file_extension);

    uk_utils_logger_info("Checking if string hello starts with 'hello'...");
    if (!uk_utils_starts_with("Hello", hello)) {
        uk_utils_stacktrace_push_msg("String hello doesn't stars with 'Hello' but it should");
        goto clean_up;
    }
    uk_utils_logger_info("OK\n");

    uk_utils_logger_info("The last index of char 'w' in string hello is at index: %d\n", uk_utils_last_index_of(hello, 'w'));
    
    uk_utils_logger_info("Reversing the string hello...");
    if ((hello = uk_utils_string_reverse(hello)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to reverse string hello");
        goto clean_up;
    }
    uk_utils_logger_info("The content of string hello is now: %s\n", hello);

    uk_utils_logger_info("Converting string_number to int...");
    uk_utils_string_to_int(string_number, &number, 10);
    if (number != 42) {
        uk_utils_stacktrace_push_msg("The number isn't equal to 42, but it should");
        goto clean_up;
    }
    uk_utils_logger_info("Number converted from string_number: %d\n", number);

    uk_utils_logger_info("Extracting the substring between indexes 11 and 21 from the string path...");
    if ((substring = uk_utils_substring(path, 13, 23)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract substring from string path");
        goto clean_up;
    }
    uk_utils_logger_info("The extracting substring is: %s\n", substring);

    uk_utils_logger_info("Extracting string from path until symbol 'h'...");
    if ((string_part = uk_utils_get_until_symbol(path, 0, 'h', &symbol_pos)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to extract string part from string path until symbol 'h'");
        goto clean_up;
    }
    uk_utils_logger_info("The symbol 'h' was found at pos %d. The string until this position is: %s\n", symbol_pos, string_part);

    uk_utils_logger_info("Removing whitespaces of string whitespaces that contains '%s'...", whitespaces);
    if ((whitespaces = uk_utils_trim_whitespace(whitespaces)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to trim whitespaces from string whitespaces");
        goto clean_up;
    }
    uk_utils_logger_info("The new content of whitespaces string is now: '%s'\n", whitespaces);

    uk_utils_logger_info("Creating an uppercased string from string path...");
    if ((uppercased = uk_utils_string_uppercase(path)) == NULL) {
        uk_utils_stacktrace_push_msg("Failed to uppercase string path");
        goto clean_up;
    }
    uk_utils_logger_info("The content of string uppercased is: '%s'", uppercased);

clean_up:
    uk_utils_safe_free(hello);
    uk_utils_safe_free(path);
    uk_utils_safe_free(file_name);
    uk_utils_safe_free(file_extension);
    uk_utils_safe_free(string_number);
    uk_utils_safe_free(substring);
    uk_utils_safe_free(string_part);
    uk_utils_safe_free(whitespaces);
    uk_utils_safe_free(uppercased);
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
