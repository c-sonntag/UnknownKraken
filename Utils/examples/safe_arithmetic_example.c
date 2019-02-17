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

bool test_add_sizet_overflow() {
    size_t one, two, out;
    int i;
    bool detected;

    one = 1;
    two = 1;
    out = 0;
    detected = false;
    
    uk_utils_logger_debug("one=%ld", one);
    uk_utils_logger_debug("two=%ld", two);
    uk_utils_logger_debug("out=%ld", out);

    for (i = 0; i < 100; i++) {
        if (uk_utils__add_overflow(one, two, &out)) {
            uk_utils_logger_info("Buffer overflow detected: %ld + %ld cannot be performed.", one, two);
            detected = true;
            break;
        }
        one = out;
        two = out;
    }

    if (!detected) {
        uk_utils_stacktrace_push_msg("Failed to detect buffer overflow when performing: %ld + %ld."
        " The result appears to be: %ld", one, two, out);
        return false;
    }

    return true;
}

bool test_safe_add() {
    int res;

    res = 0;

    uk_utils_safe_add(10, 20, &res);

    printf("%d\n", res);

    return true;
}

int main() {
    uk_utils_init_or_die();
    uk_utils_logger_use_symbol_levels();

    /*if (!test_add_sizet_overflow()) {
        uk_utils_stacktrace_push_msg("Test of uk_utils__add_sizet_overflow() failed");
        goto clean_up;
    }*/

    test_safe_add();
    
    uk_utils_logger_info("Succeed !");    

//clean_up:
    if (uk_utils_stacktrace_is_filled()) {
        uk_utils_logger_error("Error(s) occurred with the following stacktrace(s):");
        uk_utils_stacktrace_print_all();
    }
    uk_utils_uninit();
    return 0;
}
