#include <unknownecho/init.h>
#include <unknownecho/container/byte_vector.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <string.h>

int main(int argc, char **argv) {
    ue_byte_vector *vector;

    ue_init();

    if (argc != 3) {
        ue_logger_error("Invalid arguments. The input should be two bytes array.");
        goto clean_up;
    }

    vector = ue_byte_vector_create_empty();

    ue_byte_vector_append_string(vector, argv[1]);
    ue_byte_vector_append_string(vector, argv[2]);
    ue_byte_vector_append_bytes(vector, (unsigned char *)argv[1], strlen(argv[1]));

    ue_logger_info("Check if vector is empty after insertions");
    if (ue_byte_vector_is_empty(vector)) {
        ue_logger_error("Vector is empty but it shouldn't");
        goto clean_up;
    } else {
        ue_logger_info("Vector isn't empty");
    }

    ue_logger_info("Vector size : %d", ue_byte_vector_size(vector));

    ue_logger_info("Print element at index 0 :");
    ue_byte_vector_print_element(vector, 0, stdout);

    ue_logger_info("Print element at index 1 :");
    ue_byte_vector_print_element(vector, 1, stdout);

    ue_logger_info("Print all elements :");
    ue_byte_vector_print(vector, stdout);

    ue_logger_info("Check if vector contains '%s'", argv[1]);

    if (ue_byte_vector_contains(vector, (unsigned char *)argv[1], strlen(argv[1]))) {
        ue_logger_info("Specified element is in the vector");
    } else {
        ue_logger_error("Specified element isn't in the vector");
    }

clean_up:
    ue_byte_vector_destroy(vector);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
