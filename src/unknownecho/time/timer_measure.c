#include <unknownecho/time/timer_measure.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/stacktrace.h>
#include <unknownecho/string/string_utility.h>

#include <time.h>

static bool validate_unity(char *unity) {
	return unity &&
		(strcmp(unity, "ms") == 0 ||
		strcmp(unity, "us") == 0 ||
		strcmp(unity, "s") == 0);
}

ue_timer_measure *ue_timer_measure_create(unsigned int id) {
	ue_timer_measure *measure;

	ue_safe_alloc(measure, ue_timer_measure, 1);

	measure->id = id;
	measure->times_begin = NULL;
	measure->times_end = NULL;
	measure->times_begin_number = 0;
	measure->times_end_number = 0;
	measure->unity = ue_string_create_from("ms");

	return measure;
}

void ue_timer_measure_destroy(ue_timer_measure *measure) {
	if (measure) {
		ue_safe_free(measure->times_begin);
		ue_safe_free(measure->times_end);
		ue_safe_free(measure);
	}
}

char *ue_timer_measure_get_unity(ue_timer_measure *measure) {
	return measure->unity;
}

bool ue_timer_measure_set_unity(ue_timer_measure *measure, char *unity) {
	if (measure && validate_unity(unity)) {
		measure->unity = unity;
		return true;
	}
	return false;
}

bool ue_timer_measure_append_begin(ue_timer_measure *measure, int time) {
	ue_safe_realloc(measure->times_begin, int, measure->times_begin_number, 1);
	measure->times_begin[measure->times_begin_number] = time;
	measure->times_begin_number++;

	return true;
}

bool ue_timer_measure_append_end(ue_timer_measure *measure, int time) {
	ue_safe_realloc(measure->times_end, int, measure->times_end_number, 1);
	measure->times_end[measure->times_end_number] = time;
	measure->times_end_number++;

	return true;
}

bool ue_timer_measure_average(ue_timer_measure *measure, double *result) {
	double sum;
	unsigned int i;

	sum = 0.0;
	*result = 0.0;

	if (measure->times_begin_number < measure->times_end_number) {
		ue_stacktrace_push_msg("There's less times start than times end");
		return false;
	}
	else if (measure->times_begin_number > measure->times_end_number) {
		ue_stacktrace_push_msg("There's more times start than times end");
		return false;
	} else if (measure->times_begin_number == 0 && measure->times_end_number == 0) {
		ue_stacktrace_push_msg("Couple of times are equals to 0");
		return false;
	}

	for (i = 0; i < measure->times_begin_number; i++) {
		sum += (double)(measure->times_end[i] - measure->times_begin[i]);
	}

	*result = (double)(sum / measure->times_begin_number);

	return true;
}
