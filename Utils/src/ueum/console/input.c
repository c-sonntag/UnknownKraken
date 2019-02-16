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

#include <ueum/console/input.h>
#include <ueum/string/string_utility.h>
#include <ueum/safe/safe_alloc.h>

#include <ei/ei.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>  /* for errno */

#if defined(__unix__)
    #include <unistd.h> /* for EINTR */
#endif

char *ueum_input_string(char *prefix) {
    char input[256], *result;
    int i;

    result = NULL;

    printf("%s", prefix);

      if (fgets(input, 256, stdin)) {
        if (input[0] == 10) {
              return NULL;
        }
        for (i = 0; i < 256; i++) {
            if (input[i] != ' ') {
                result = ueum_string_create_from(input);
                ueum_remove_last_char(result);
                break;
            }
        }
      }

      return result;
}

#if defined(__unix__)

#include <termios.h>
#include <sys/time.h>

/**
 * Get the password enter in input stream without print it in the terminal.
 * It only works on Linux/Mac.
 *
 * Read a string from stream into password masking keypress with mask char.
 * getpasswd will read upto max_size - 1 chars into password, null-terminating
 * the resulting string. On success, the number of characters in
 * password are returned, -1 otherwise.
 *
 * @param password where to password will be stored. It have to be allocated by the caller.
 * @param max_size max size of the password, set by the caller.
 * @param stream   input stream, e.g. stdin.
 * @return the size of the input password.
 * @todo record error messages in place of print them.
 *
 * @source https://stackoverflow.com/a/32421674
 */
static ssize_t get_input_password_unix(char **password, ssize_t max_size, int mask, FILE *stream) {
    ssize_t idx; /* index, number of chars in read   */
    int c;
    struct termios old_kbd_mode; /* Orig keyboard settings   */
    struct termios new_kbd_mode;

    /**
     * Validate input
     * @todo check each parameter to detail error message
     */
    if (!password || !max_size || !stream) {
        ei_stacktrace_push_msg("At least one invalid parameter");
        return -1;
    }

    idx = 0;
    c = 0;

    /* Save orig settings */
    if (tcgetattr(0, &old_kbd_mode)) {
        ei_stacktrace_push_msg("tcgetattr failed");
        return -1;
    }

    /* Copy old to new */
    memcpy(&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

    new_kbd_mode.c_lflag &= ~(ICANON | ECHO); /* New kbd flags */
    new_kbd_mode.c_cc[VTIME] = 0;
    new_kbd_mode.c_cc[VMIN] = 1;
    if (tcsetattr(0, TCSANOW, &new_kbd_mode)) {
        ei_stacktrace_push_msg("tcsetattr failed with new flags");
        return -1;
    }

    /* Read chars from stream, mask if valid char specified */
    while (((c = fgetc(stream)) != '\n' && c != EOF && idx < max_size - 1) ||
            (idx == max_size - 1 && c == 127)) {
        if (c != 127) {
            /* Valid ascii char */
            if (31 < mask && mask < 127) {
                fputc(mask, stdout);
            }
            (*password)[idx++] = c;
        }
        else if (idx > 0) {
            /* Handle backspace (del) */
            if (31 < mask && mask < 127) {
                fputc(0x8, stdout);
                fputc(' ', stdout);
                fputc(0x8, stdout);
            }
            (*password)[--idx] = 0;
        }
    }
    /* Set null-terminate */
    (*password)[idx] = 0;

    /* Reset original keyboard */
    if (tcsetattr(0, TCSANOW, &old_kbd_mode)) {
        ei_stacktrace_push_msg("tcsetattr failed to set previous flags");
        return -1;
    }

    /* Warn if password truncated */
    if (idx == max_size - 1 && c != '\n') {
        ei_logger_warn("Truncated at %zu chars", max_size - 1);
    }

    return idx;
}

#endif

#if defined(_WIN32) || defined(_WIN64)

/**
 * @see http://www.cplusplus.com/articles/E6vU7k9E/
 */
static ssize_t get_input_password_windows(char **password, ssize_t max_size, FILE *stream) {
    (void)password;
    (void)max_size;
    (void)stream;
    ei_stacktrace_push_msg("Not implemented");
    return -1;
}

#endif

/**
 * Get the password enter in input stream without print it in the terminal.
 */
char *ueum_input_password(const char *prompt_message, ssize_t max_size) {
    char *password;
    ssize_t size;

    password = NULL;

    ueum_safe_alloc(password, char, max_size);
    size = 0;

#if defined(__unix__)
    printf("%s", prompt_message);
    size = get_input_password_unix(&password, max_size, '*', stdin);
    printf("\n");
#elif defined(_WIN32) || defined(_WIN64)
    printf("%s", prompt_message);
    size = get_input_password_windows(&password, max_size, stdin);
    printf("\n");
#else
    #error Unsupported operating system
#endif

    if (size == -1) {
        ueum_safe_free(password);
        return password;
    }

    if (size < max_size) {
        ueum_safe_realloc(password, char, size, max_size - size);
    }

    return password;
}
