#include <unknownecho/time/clock_time_posix.h>

#include <time.h>
#include <sys/time.h>

/**
 * Source : https://stackoverflow.com/a/37920181
 */
unsigned long long ue_get_posix_clock_time() {
    struct timespec ts;
    struct timeval tv;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (unsigned long long) (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
    } else if (gettimeofday(&tv, NULL) == 0) {
        return (unsigned long long) (tv.tv_sec * 1000000 + tv.tv_usec);
    } else {
        return 0;
    }
}
