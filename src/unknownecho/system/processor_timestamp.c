#include <unknownecho/system/processor_timestamp.h>

/**
 * source : https://msdn.microsoft.com/en-us/library/twchhe95.aspx
 */
#if defined(__unix__)
	/**
	 * source : https://stackoverflow.com/questions/9887839/clock-cycle-count-wth-gcc
	 */
	#if defined(__i386__)
		static __inline__ unsigned long long rdtsc() {
			unsigned long long int x;
			__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
			return x;
		}
	#elif defined(__x86_64__)
		static __inline__ unsigned long long rdtsc() {
			unsigned hi, lo;
			__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
			return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
		}
	#endif
#elif defined(_WIN32) || defined(_WIN64)
	#include <intrin.h>

	#pragma intrinsic(__rdtsc)

	static unsigned long long processor_timestamp_windows() {
		unsigned __int64 i;
		i = __rdtsc();
		return (unsigned long long)i;
	}
#endif

unsigned long long ue_processor_timestamp() {
	#if defined(__unix__)
		return rdtsc();
	#elif defined(_WIN32)
		return processor_timestamp_windows();
	#endif
}
