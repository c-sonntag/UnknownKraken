#include <unknownecho/time/sleep.h>

#if defined(WIN32)
    #include <windows.h>
#else
    #include <unistd.h>
    #include <time.h>
#endif

int ue_millisleep(unsigned ms) {
	#if defined(WIN32)
		SetLastError(0);
		Sleep(ms);
		return GetLastError() ? -1 : 0;

	#elif _POSIX_C_SOURCE >= 199309L
		/* prefer to use nanosleep() */
		const struct timespec ts = {
			ms / 1000, /* seconds */
			(ms % 1000) * 1000 * 1000 /* nano seconds */
		};

		return nanosleep(&ts, NULL);

	#elif _BSD_SOURCE || \
		(_XOPEN_SOURCE >= 500 || \
		_XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED) && \
		!(_POSIX_C_SOURCE >= 200809L || _XOPEN_SOURCE >= 700)

		/* else fallback to obsolte usleep() */
		return usleep(1000 * ms);

	#else
		#error("No millisecond sleep available for this platform!")
		return -1;

	#endif
}
