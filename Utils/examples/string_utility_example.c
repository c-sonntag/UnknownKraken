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

#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stdio.h>

int main() {
    char *hello, *path, *file_name, *file_extension,
        *string_number, *substring, *string_part, *whitespaces,
        *uppercased;
    int number, symbol_pos;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    hello = NULL;
    path = NULL;
    file_name = NULL;
    file_extension = NULL;
    string_number = NULL;
    substring = NULL;
    string_part = NULL;
    whitespaces = NULL;
    uppercased = NULL;
    
    ei_logger_info("Creating string hello...");
    if ((hello = ueum_string_create_from("Hello world !")) == NULL) {
        ei_stacktrace_push_msg("Failed to create string hello");
        goto clean_up;
    }
    ei_logger_info("Original content of string hello is: %s\n", hello);

    ei_logger_info("Creating string path...");
    if ((path = ueum_string_create_from("/usr/include/ueum/ueum.h")) == NULL) {
        ei_stacktrace_push_msg("Failed to create string path");
        goto clean_up;
    }
    ei_logger_info("Original content of string path is: %s\n", path);

    ei_logger_info("Creating string string_number...");
    if ((string_number = ueum_string_create_from("42")) == NULL) {
        ei_stacktrace_push_msg("Failed to create string string_number");
        goto clean_up;
    }
    ei_logger_info("Original content of string string_number is: %s\n", string_number);

    ei_logger_info("Creating string whitespaces...");
    if ((whitespaces = ueum_string_create_from("123   ")) == NULL) {
        ei_stacktrace_push_msg("Failed to create string whitespaces");
        goto clean_up;
    }
    ei_logger_info("Original content of string whitespaces is: %s\n", whitespaces);

    ei_logger_info("Removing the last char of string hello...");
    ueum_remove_last_char(hello);
    ei_logger_info("The content of string hello is now: %s\n", hello);

    ei_logger_info("Verifiying that the last char of the modified string is a space...");
    if (!ueum_last_char_is(hello, ' ')) {
        ei_stacktrace_push_msg("The last char isn't a space");
        goto clean_up;
    }
    ei_logger_info("OK\n");

    ei_logger_info("The position of string 'world' is at index: %d\n", ueum_find_str_in_data(hello, "world"));

    ei_logger_info("Extracting the file name from string path...");
    if ((file_name = ueum_get_file_name_from_path(path)) == NULL) {
        ei_stacktrace_push_msg("Failed to extract file name from string path");
        goto clean_up;
    }
    ei_logger_info("The file name of the path is: %s\n", file_name);

    ei_logger_info("Extracting the file extension from string file_name...");
    if ((file_extension = ueum_get_file_extension(file_name)) == NULL) {
        ei_stacktrace_push_msg("Failed to get file extension from string file_name");
        goto clean_up;
    }
    ei_logger_info("The file extension of the file is: %s\n", file_extension);

    ei_logger_info("Checking if string hello starts with 'hello'...");
    if (!ueum_starts_with("Hello", hello)) {
        ei_stacktrace_push_msg("String hello doesn't stars with 'Hello' but it should");
        goto clean_up;
    }
    ei_logger_info("OK\n");

    ei_logger_info("The last index of char 'w' in string hello is at index: %d\n", ueum_last_index_of(hello, 'w'));
    
    ei_logger_info("Reversing the string hello...");
    if ((hello = ueum_string_reverse(hello)) == NULL) {
        ei_stacktrace_push_msg("Failed to reverse string hello");
        goto clean_up;
    }
    ei_logger_info("The content of string hello is now: %s\n", hello);

    ei_logger_info("Converting string_number to int...");
    ueum_string_to_int(string_number, &number, 10);
    if (number != 42) {
        ei_stacktrace_push_msg("The number isn't equal to 42, but it should");
        goto clean_up;
    }
    ei_logger_info("Number converted from string_number: %d\n", number);

    ei_logger_info("Extracting the substring between indexes 11 and 21 from the string path...");
    if ((substring = ueum_substring(path, 13, 23)) == NULL) {
        ei_stacktrace_push_msg("Failed to extract substring from string path");
        goto clean_up;
    }
    ei_logger_info("The extracting substring is: %s\n", substring);

    ei_logger_info("Extracting string from path until symbol 'h'...");
    if ((string_part = ueum_get_until_symbol(path, 0, 'h', &symbol_pos)) == NULL) {
        ei_stacktrace_push_msg("Failed to extract string part from string path until symbol 'h'");
        goto clean_up;
    }
    ei_logger_info("The symbol 'h' was found at pos %d. The string until this position is: %s\n", symbol_pos, string_part);

    ei_logger_info("Removing whitespaces of string whitespaces that contains '%s'...", whitespaces);
    if ((whitespaces = ueum_trim_whitespace(whitespaces)) == NULL) {
        ei_stacktrace_push_msg("Failed to trim whitespaces from string whitespaces");
        goto clean_up;
    }
    ei_logger_info("The new content of whitespaces string is now: '%s'\n", whitespaces);

    ei_logger_info("Creating an uppercased string from string path...");
    if ((uppercased = ueum_string_uppercase(path)) == NULL) {
        ei_stacktrace_push_msg("Failed to uppercase string path");
        goto clean_up;
    }
    ei_logger_info("The content of string uppercased is: '%s'", uppercased);

clean_up:
    ueum_safe_free(hello);
    ueum_safe_free(path);
    ueum_safe_free(file_name);
    ueum_safe_free(file_extension);
    ueum_safe_free(string_number);
    ueum_safe_free(substring);
    ueum_safe_free(string_part);
    ueum_safe_free(whitespaces);
    ueum_safe_free(uppercased);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ei_uninit();
    return 0;
}
