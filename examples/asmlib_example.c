#include <unknownecho/init.h>
#include <unknownecho/time/timer.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/bool.h>

#include "asmlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#define TEST_MEMCPY   1
#define TEST_A_MEMCPY 2

bool test_memcpy(char *string) {
    int i;
    char *dest;
    size_t len;
    bool r;

    len = strlen(string);

    ue_safe_alloc(dest, char, len);

    for (i = 0; i < 1000000; i++) {
        ue_timer_start(TEST_MEMCPY);
        //memcpy(dest, string, len * sizeof(char));
        //memset(dest, 0, len * sizeof(char));
        //r = memcmp(string, string, len) == 0;
        //strcat(dest, string);
        //strcpy(dest, string);
        r = strcmp(string, string) == 0;
        ue_timer_stop(TEST_MEMCPY);
        //memset(dest, 0, len * sizeof(char));
    }

    printf("r : %d\n", r);

    ue_safe_free(dest);

    return true;
}

bool test_A_memcpy(char *string) {
    int i;
    char *dest;
    size_t len;
    bool r;

    len = strlen(string);

    ue_safe_alloc(dest, char, len);

    for (i = 0; i < 1000000; i++) {
        ue_timer_start(TEST_A_MEMCPY);
        //A_memcpy(dest, string, len * sizeof(char));
        //A_memset(dest, 0, len * sizeof(char));
        //A_memcmp(string, string, len);
        //A_strcat(dest, string);
        //A_strcpy(dest, string);
        r = A_strcmp(string, string) == 0;
        ue_timer_stop(TEST_A_MEMCPY);
        //memset(dest, 0, len * sizeof(char));
    }

    printf("r : %d\n", r);

    ue_safe_free(dest);

    return true;
}

/**
 * [SLOWER] A_memcpy
 * [TODO] A_memmove
 * [FASTER] A_memset
 * [FASTER] A_memcmp
 * [SLOWER] A_strcat
 * [FASTER] A_strcpy
 * [FASTER] A_strlen
 */
int main(int argc, char **argv) {
    char *processor_name;
    int vendor, family, model, i;

    ue_init();

    /*test_A_memcpy(argv[1]);

    test_memcpy(argv[1]);

    ue_timer_average_print(TEST_MEMCPY, "memcpy");

    ue_timer_average_print(TEST_A_MEMCPY, "A_memcpy");*/

    processor_name = NULL;
    vendor = 0;
    family = 0;
    model = 0;

    processor_name = ProcessorName();
    CpuType(&vendor, &family, &model);

    if (processor_name) {
        printf("processor_name : %s\n", processor_name);
    }

    printf("vendor : %d\n", vendor);
    printf("family : %d\n", family);
    printf("model : %d\n", model);

    for (i = 0; i < 10; i++) {
        printf("ReadTSC() : %u\n", ReadTSC());
    }

    ue_uninit();

	exit(EXIT_SUCCESS);
}
