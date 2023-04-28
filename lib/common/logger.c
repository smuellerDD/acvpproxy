/* Logging support
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "aux_helper.h"
#include "binhexbin.h"
#include "build_bug_on.h"
#include "constructor.h"
#include "logger.h"
#include "term_colors.h"
#include "threading_support.h"

static enum logger_verbosity logger_verbosity_level = LOGGER_STATUS;
static enum logger_class logger_class_level = LOGGER_C_ANY;

struct logger_class_map {
	const enum logger_class class;
	const char *logdata;
};

static FILE *logger_stream = NULL;

static const struct logger_class_map logger_class_mapping[] = {
	{ LOGGER_C_ANY, NULL },
	{ LOGGER_C_THREADING, "Threading support" },
	{ LOGGER_C_MQSERVER, "TOTP MQ System" },
	{ LOGGER_C_SLEEP, "Sleep management" },
	{ LOGGER_C_SIGNALHANDLER, "Signal handler" },
	{ LOGGER_C_DS_FILE, "File backend" },
	{ LOGGER_C_TOTP, "TOTP generation" },
	{ LOGGER_C_CURL, "HTTP operation" },
};

static void logger_severity(enum logger_verbosity severity, char *sev,
			    const unsigned int sevlen)
{
	switch (severity) {
	case LOGGER_DEBUG2:
		snprintf(sev, sevlen, "Debug2");
		break;
	case LOGGER_DEBUG:
		snprintf(sev, sevlen, "Debug");
		break;
	case LOGGER_VERBOSE:
		snprintf(sev, sevlen, "Verbose");
		break;
	case LOGGER_WARN:
		snprintf(sev, sevlen, "Warning");
		break;
	case LOGGER_ERR:
		snprintf(sev, sevlen, "Error");
		break;
	case LOGGER_STATUS:
		snprintf(sev, sevlen, "Status");
		break;
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		snprintf(sev, sevlen, "Unknown");
	}
}

static int logger_class_idx(enum logger_class class, unsigned int *idx)
{
	unsigned int i;

	*idx = 0;

	if (logger_class_level != LOGGER_C_ANY && logger_class_level != class)
		return -EOPNOTSUPP;

	for (i = 0; i < ARRAY_SIZE(logger_class_mapping); i++) {
		if (class == logger_class_mapping[i].class) {
			*idx = i;

			return 0;
		}
	}

	return -EINVAL;
}

static int logger_class(const enum logger_class class, char *s,
			const unsigned int slen)
{
	unsigned int idx;
	int ret = logger_class_idx(class, &idx);

	if (ret)
		return ret;

	if (logger_class_mapping[idx].logdata)
		snprintf(s, slen, " - %s", logger_class_mapping[idx].logdata);
	else
		s[0] = '\0';

	return 0;
}

DSO_PUBLIC
void _logger(const enum logger_verbosity severity,
	     const enum logger_class class, const char *file, const char *func,
	     const uint32_t line, const char *fmt, ...)
{
	time_t now;
	struct tm now_detail;
	va_list args;
	int (*fprintf_color)(FILE * stream, const char *format, ...) = &fprintf;
	int ret;
	char msg[4096];
	char sev[10];
	char c[30];
	char thread_name[ACVP_THREAD_MAX_NAMELEN];

	if (!logger_stream)
		logger_stream = stderr;

	if (severity > logger_verbosity_level)
		return;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	logger_severity(severity, sev, sizeof(sev));
	ret = logger_class(class, c, sizeof(c));
	if (ret)
		return;

	now = time(NULL);
	localtime_r(&now, &now_detail);

	switch (severity) {
	case LOGGER_DEBUG2:
		fprintf_color = &fprintf_cyan;
		break;
	case LOGGER_DEBUG:
		fprintf_color = &fprintf_blue;
		break;
	case LOGGER_VERBOSE:
		fprintf_color = &fprintf_green;
		break;
	case LOGGER_WARN:
		fprintf_color = &fprintf_yellow;
		break;
	case LOGGER_ERR:
		fprintf_color = &fprintf_red;
		break;
	case LOGGER_STATUS:
		fprintf_color = &fprintf_magenta;
		break;
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		fprintf_color = &fprintf;
	}

	thread_get_name(thread_name, sizeof(thread_name));

	switch (logger_verbosity_level) {
	case LOGGER_DEBUG2:
	case LOGGER_DEBUG:
		fprintf_color(
			logger_stream,
			"ACVPProxy (%.2d:%.2d:%.2d) (%s) %s%s [%s:%s:%u]: ",
			now_detail.tm_hour, now_detail.tm_min,
			now_detail.tm_sec, thread_name, sev, c, file, func,
			line);
		break;
	case LOGGER_VERBOSE:
	case LOGGER_WARN:
	case LOGGER_ERR:
	case LOGGER_STATUS:
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		fprintf_color(logger_stream,
			      "ACVPProxy (%.2d:%.2d:%.2d) (%s) %s%s: ",
			      now_detail.tm_hour, now_detail.tm_min,
			      now_detail.tm_sec, thread_name, sev, c);
		break;
	}

	fprintf(logger_stream, "%s", msg);
}

DSO_PUBLIC
void _logger_binary(const enum logger_verbosity severity,
		    const enum logger_class class, const unsigned char *bin,
		    const uint32_t binlen, const char *str, const char *file,
		    const char *func, const uint32_t line)
{
	time_t now;
	struct tm now_detail;
	int ret;
	char sev[10];
	char msg[4096];
	char c[30];

	if (severity > logger_verbosity_level)
		return;

	logger_severity(severity, sev, sizeof(sev));

	now = time(NULL);
	localtime_r(&now, &now_detail);

	ret = logger_class(class, c, sizeof(c));
	if (ret)
		return;

	switch (logger_verbosity_level) {
	case LOGGER_DEBUG2:
	case LOGGER_DEBUG:
		snprintf(msg, sizeof(msg),
			 "ACVPProxy (%.2d:%.2d:%.2d) %s%s [%s:%s:%u]: %s",
			 now_detail.tm_hour, now_detail.tm_min,
			 now_detail.tm_sec, sev, c, file, func, line, str);
		break;
	case LOGGER_VERBOSE:
	case LOGGER_WARN:
	case LOGGER_ERR:
	case LOGGER_STATUS:
	case LOGGER_NONE:
	case LOGGER_MAX_LEVEL:
	default:
		snprintf(msg, sizeof(msg),
			 "ACVPProxy (%.2d:%.2d:%.2d) %s%s: %s",
			 now_detail.tm_hour, now_detail.tm_min,
			 now_detail.tm_sec, sev, c, str);
		break;
	}

	bin2print(bin, binlen, logger_stream, msg);
}

DSO_PUBLIC
void logger_spinner(const unsigned int percentage, const char *fmt, ...)
{
	static unsigned int start = 0;

	if (logger_verbosity_level > LOGGER_ERR)
		return;

	if (percentage >= 100) {
		if (start < 2) {
			fprintf(stderr, "\n");
			start = 2;
		}
		return;
	}

	if (start) {
		unsigned int i;

		for (i = 0; i < 4; i++)
			fprintf(stderr, "\b");
	} else {
		va_list args;
		char msg[4096];

		va_start(args, fmt);
		vsnprintf(msg, sizeof(msg), fmt, args);
		va_end(args);

		fprintf(stderr, "ACVPProxy progress: %s ", msg);
		start = 1;
	}

	fprintf(stderr, "%.3u%%", percentage);

	fflush(stderr);
}

static void logger_destructor(void)
{
	if (logger_stream && logger_stream != stderr)
		fclose(logger_stream);
}

ACVP_DEFINE_CONSTRUCTOR(logger_constructor)
static void logger_constructor(void)
{
	logger_stream = stderr;
}

FILE *logger_log_stream(void)
{
	return logger_stream;
}

DSO_PUBLIC
int logger_set_file(const char *pathname)
{
	FILE *out;

	out = fopen(pathname, "a");
	if (!out)
		return -errno;

	if (!logger_stream || logger_stream == stderr)
		logger_stream = out;
	else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Reject to set new log file\n");
		return -EFAULT;
	}
	atexit(logger_destructor);

	return 0;
}

DSO_PUBLIC
void logger_set_verbosity(const enum logger_verbosity level)
{
	logger_verbosity_level = level;
}

DSO_PUBLIC
int logger_set_class(enum logger_class class)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(logger_class_mapping); i++) {
		if (class == logger_class_mapping[i].class) {
			logger_class_level = class;
			return 0;
		}
	}

	return -EINVAL;
}

DSO_PUBLIC
void logger_get_class(const int fd)
{
	unsigned int i;

	/* Ensure that logger_class_mapping contains all LOGGER_C_ enums */
	BUILD_BUG_ON(ARRAY_SIZE(logger_class_mapping) != LOGGER_C_LAST);

	for (i = 0; i < ARRAY_SIZE(logger_class_mapping); i++) {
		dprintf(fd, "%u %s\n", logger_class_mapping[i].class,
			logger_class_mapping[i].logdata ?
				      logger_class_mapping[i].logdata :
				      "(unclassified)");
	}
}

DSO_PUBLIC
enum logger_verbosity logger_get_verbosity(const enum logger_class class)
{
	unsigned int idx;

	if (logger_class_idx(class, &idx))
		return LOGGER_NONE;
	return logger_verbosity_level;
}

DSO_PUBLIC
void logger_inc_verbosity(void)
{
	if (logger_verbosity_level >= LOGGER_MAX_LEVEL - 1)
		return;

	logger_verbosity_level++;
}
