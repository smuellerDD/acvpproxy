/* Logging support
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "binhexbin.h"
#include "build_bug_on.h"
#include "logger.h"
#include "term_colors.h"

#include "internal.h"

static enum logger_verbosity logger_verbosity_level = LOGGER_NONE;
static enum logger_class logger_class_level = LOGGER_C_ANY;

struct logger_class_map {
	const enum logger_class class;
	const char *logdata;
};

static const struct logger_class_map logger_class_mapping[] =
{
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
			    unsigned int sevlen)
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

static int logger_class(enum logger_class class, char *s, unsigned int slen)
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
void logger(enum logger_verbosity severity, enum logger_class class,
	    const char *fmt, ...)
{
	time_t now;
	struct tm now_detail;
	va_list args;
	int(* fprintf_color)(FILE *stream, const char *format, ...) = &fprintf;
	int ret;
	char msg[4096];
	char sev[10];
	char c[30];

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
	default:
		fprintf_color = &fprintf;
	}

	fprintf_color(stderr, "ACVPProxy (%.2d:%.2d:%.2d) %s%s: ",
		      now_detail.tm_hour, now_detail.tm_min, now_detail.tm_sec,
		      sev, c);
	fprintf(stderr, "%s", msg);
}

DSO_PUBLIC
void logger_status(enum logger_class class, const char *fmt, ...)
{
	time_t now;
	struct tm now_detail;
	va_list args;
	int ret;
	char msg[256];
	char c[30];

	if (logger_verbosity_level != LOGGER_WARN &&
	    logger_verbosity_level != LOGGER_ERR)
		return;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	now = time(NULL);
	localtime_r(&now, &now_detail);

	ret = logger_class(class, c, sizeof(c));
	if (ret)
		return;

	fprintf_magenta(stderr, "ACVPProxy (%.2d:%.2d:%.2d) Status%s: ",
			now_detail.tm_hour, now_detail.tm_min,
			now_detail.tm_sec, c);
	fprintf(stderr, "%s", msg);
}

DSO_PUBLIC
void logger_binary(enum logger_verbosity severity, enum logger_class class,
		   const unsigned char *bin, uint32_t binlen, const char *str)
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

	snprintf(msg, sizeof(msg), "ACVPProxy (%.2d:%.2d:%.2d) %s%s: %s",
		 now_detail.tm_hour, now_detail.tm_min, now_detail.tm_sec,
		 sev, c, str);
	bin2print(bin, binlen, stderr, msg);
}

DSO_PUBLIC
void logger_set_verbosity(enum logger_verbosity level)
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
void logger_get_class(int fd)
{
	unsigned int i;

	/* Ensure that logger_class_mapping contains all LOGGER_C_ enums */
	BUILD_BUG_ON(ARRAY_SIZE(logger_class_mapping) != LOGGER_C_LAST);

	for (i = 0; i < ARRAY_SIZE(logger_class_mapping); i++) {
		dprintf(fd, "%u %s\n", logger_class_mapping[i].class,
			logger_class_mapping[i].logdata ?
			logger_class_mapping[i].logdata : "(unclassified)");
	}
}

DSO_PUBLIC
enum logger_verbosity logger_get_verbosity(enum logger_class class)
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
