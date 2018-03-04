#include <unknownecho/init.h>
#include <unknownecho/errorHandling/logger.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/byte/byte_split.h>
#include <unknownecho/string/string_utility.h>
#include <unknownecho/system/alloc.h>

#include <string.h>
#include <stddef.h>
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char **split;
    size_t count, *sizes, i;
    char *buffer;

    split = NULL;
    sizes = NULL;

    ue_init();

    if (argc != 3) {
        ue_logger_error("Invalid arguments. The input should be two bytes array.");
        goto clean_up;
    }

    if (!(split = ue_byte_split((unsigned char *)argv[1], strlen(argv[1]), (unsigned char *)argv[2], strlen(argv[2]), &count, &sizes))) {
		ue_logger_info("Delimiter not found is this byte array");
		goto clean_up;
	}

    for (i = 0; i < count; i++) {
        buffer = ue_string_create_from_bytes(split[i], sizes[i]);
        printf("sizes[%d] : %ld ", i, sizes[i]);
        printf("%s\n", buffer);
        ue_safe_free(buffer);
    }

clean_up:
    if (split) {
        for (i = 0; i < count; i++) {
            ue_safe_free(split[i]);
        }
        ue_safe_free(split);
    }
    ue_safe_free(sizes);
    if (ue_stacktrace_is_filled()) {
        ue_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ue_stacktrace_print_all();
    }
    ue_uninit();
    return 0;
}
