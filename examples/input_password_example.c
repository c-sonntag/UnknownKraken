#include <unknownecho/init.h>
#include <unknownecho/console/input.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/alloc.h>

#include <stdio.h>
#include <stdlib.h>

int main() {
    char *password;

    password = NULL;

    if (!ue_init()) {
        fprintf(stderr, "[FATAL] Failed to initialize UnknownEchoLib\n");
        exit(EXIT_FAILURE);
    }
    ue_logger_info("UnknownEchoLib is correctly initialized");
    
    if (!(password = ue_input_password("Enter a password: ", 32))) {
        ue_stacktrace_push_msg("Failed to get input password");
        goto clean_up;
    }

    ue_logger_info("The password is: %s", password);

clean_up:
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("An error occurred with the following stacktrace :");
        ue_stacktrace_print_all();
    }
    ue_safe_free(password);
    return EXIT_SUCCESS;
}
