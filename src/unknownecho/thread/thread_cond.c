#include <unknownecho/thread/thread_cond.h>
#include <unknownecho/system/alloc.h>
#include <unknownecho/errorHandling/check_parameter.h>
#include <unknownecho/errorHandling/stacktrace.h>

#include <errno.h>

ue_thread_cond *ue_thread_cond_create() {
	ue_thread_cond *cond;

	ue_safe_alloc(cond, ue_thread_cond, 1);

	if (pthread_cond_init(&cond->data, NULL) != 0) {
		ue_stacktrace_push_errno();
		goto clean_up;
	}

	return cond;

clean_up:
	ue_safe_free(cond);
	return NULL;
}

void ue_thread_cond_destroy(ue_thread_cond *cond) {
	if (cond) {
		pthread_cond_destroy(&cond->data);
		ue_safe_free(cond);
	}
}

bool ue_thread_cond_wait(ue_thread_cond *cond, ue_thread_mutex *mutex) {
	ue_check_parameter_or_return(cond);
	ue_check_parameter_or_return(mutex);

	if (pthread_cond_wait(&cond->data, &mutex->lock) != 0) {
		if (errno != ETIMEDOUT) {
			ue_stacktrace_push_errno();
			return false;
		}
	}

	return true;
}

bool ue_thread_cond_signal(ue_thread_cond *cond) {
	ue_check_parameter_or_return(cond);

	if (pthread_cond_signal(&cond->data) != 0) {
		ue_stacktrace_push_errno();
		return false;
	}

	return true;
}

bool ue_thread_cond_broadcast(ue_thread_cond *cond) {
	ue_check_parameter_or_return(cond);

	if (pthread_cond_broadcast(&cond->data) != 0) {
		ue_stacktrace_push_errno();
		return false;
	}

	return true;
}
