/* Sleeper helper
 *
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "logger.h"
#include "sleep.h"

/*****************************************************************************
 * Interruptible sleep and wait helper
 *****************************************************************************/

#define min(x, y) ((x < y) ? x : y)

static inline uint64_t sleep_sec2nsec(uint64_t seconds)
{
	return (seconds * 1000 * 1000 * 1000);
}

/* Convert struct timespec into integer with nanoseconds */
static inline uint64_t sleep_timespec2nsec(const struct timespec *time)
{
	return ((uint64_t)sleep_sec2nsec((uint64_t)time->tv_sec) +
		(uint64_t)time->tv_nsec);
}

/*
 * Get time duration that was slept in nsec using the time to sleep and the
 * remaining time as returned by nanosleep(2).
 */
static inline uint64_t sleep_time_slept(const struct timespec *hibernate,
					const struct timespec *remain)
{
	uint64_t hibernate_nsec = sleep_timespec2nsec(hibernate);
	uint64_t remain_nsec = sleep_timespec2nsec(remain);

	if (hibernate_nsec < remain_nsec)
		return 0;

	return (hibernate_nsec - remain_nsec);
}

static inline void sleep_adjust_time(uint64_t *sleep_time_ns, uint64_t nsec)
{
	*sleep_time_ns -= min(*sleep_time_ns, nsec);
}

int sleep_interruptible(unsigned int sleep_time, atomic_bool_t *interrupted)
{
	const struct timespec hibernate = { .tv_sec = SLEEP_SLEEPTIME_SECONDS,
					    .tv_nsec = 0 };
	struct timespec remain = { .tv_sec = 0, .tv_nsec = 0};
	uint64_t slept, sleep_time_ns = sleep_sec2nsec(sleep_time);
	int ret;

	if (sleep_time < (uint64_t)hibernate.tv_sec) {
		logger(LOGGER_ERR, LOGGER_C_SLEEP,
		       "Requested sleep time too small (minimum required sleep time is %u seconds + %u nanoseconds)\n",
		       hibernate.tv_sec, hibernate.tv_nsec);
		return -EINVAL;
	}

	/* Busy-wait to constantly monitor the interrupted parameter */
	while (sleep_time_ns) {
		/* Are we shutting down? */
		if (interrupted && atomic_bool_read(interrupted)) {
			logger(LOGGER_VERBOSE, LOGGER_C_SLEEP,
			       "Sleep interrupted (time slept: %lu nsec)\n",
			       sleep_sec2nsec(sleep_time) - sleep_time_ns);
			return -EINTR;
		}

		ret = nanosleep(&hibernate, &remain);
		if (ret < 0) {
			if (errno != EINTR)
				return -errno;
			slept = sleep_time_slept(&hibernate, &remain);
		} else {
			slept = sleep_timespec2nsec(&hibernate);
		}
		sleep_adjust_time(&sleep_time_ns, slept);
	}

	return 0;
}

/*****************************************************************************
 * Print time duration
 *****************************************************************************/

static inline uint64_t duration_time(const struct timespec *start,
				     const struct timespec *end)
{
	return sleep_time_slept(end, start);
}

int duration_string(const struct timespec *start,
		    char *buf, unsigned int buflen)
{
	struct timespec end;
	uint64_t hour, min, sec, milli, micro, nano;

	if (clock_gettime(CLOCK_REALTIME, &end))
		return -errno;

	nano = duration_time(start, &end);

	if (nano < 1000) {
		snprintf(buf, buflen, "%" PRIu64 " ns", nano);
		return 0;
	}

	micro = nano / 1000;
	if (micro < 1000) {
		snprintf(buf, buflen, "%" PRIu64 ".%.1" PRIu64 " us",
			 micro, nano % 1000);
		return 0;
	}

	milli = micro / 1000;
	if (milli < 1000) {
		snprintf(buf, buflen, "%" PRIu64 ".%.1" PRIu64 " ms",
			 milli, micro % 1000);
		return 0;
	}

	sec = milli / 1000;
	hour = sec / 3600;
	sec -= hour * 3600;
	min = sec / 60;
	sec = sec - (min * 60);

	if (hour)
		snprintf(buf,
			 buflen, "%.3" PRIu64 ":%.2" PRIu64 ":%.2" PRIu64 ".%.1" PRIu64 " h",
			 hour, min, sec, milli % 1000);
	else if (min)
		snprintf(buf,
			 buflen, "%.2" PRIu64 ":%.2" PRIu64 ".%.1" PRIu64 " min",
			 min, sec, milli % 1000);
	else
		snprintf(buf, buflen, "%" PRIu64 ".%.1" PRIu64 " s",
			 sec, milli % 1000);

	return 0;
}
