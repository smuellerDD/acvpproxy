/*
* Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

enum logger_verbosity {
	LOGGER_NONE,
	LOGGER_STATUS,
	LOGGER_ERR,
	LOGGER_WARN,
	LOGGER_VERBOSE,
	LOGGER_DEBUG,
	LOGGER_DEBUG2,

	LOGGER_MAX_LEVEL /* This must be last entry */
};

enum logger_class {
	LOGGER_C_ANY,
	LOGGER_C_THREADING,
	LOGGER_C_MQSERVER,
	LOGGER_C_SLEEP,
	LOGGER_C_SIGNALHANDLER,
	LOGGER_C_DS_FILE,
	LOGGER_C_TOTP,
	LOGGER_C_CURL,

	LOGGER_C_LAST /* This must be last entry */
};

/* Helper that is not intended to be called directly */
void _logger(const enum logger_verbosity severity,
	     const enum logger_class class, const char *file, const char *func,
	     const uint32_t line, const char *fmt, ...)
	__attribute__((format(printf, 6, 7)));
void _logger_binary(const enum logger_verbosity severity,
		    const enum logger_class class, const unsigned char *bin,
		    const uint32_t binlen, const char *str, const char *file,
		    const char *func, const uint32_t line);

/**
 * logger - log string with given severity
 * @param severity maximum severity level that causes the log entry to be logged
 * @param class logging class
 * @param fmt format string as defined by fprintf(3)
 */
#define logger(severity, class, fmt...)					       \
	do {								       \
		_Pragma("GCC diagnostic push")                                 \
		_Pragma("GCC diagnostic ignored \"-Wpedantic\"") 	       \
		_logger(severity, class, __FILE__, 		   	       \
			__FUNCTION__, __LINE__, ##fmt);			       \
		_Pragma("GCC diagnostic pop")				       \
	} while (0);

/**
 * logger - log status if LOGGER_WARN or LOGGER_ERR is found
 * @param class logging class
 * @param fmt format string as defined by fprintf(3)
 */
#define logger_status(class, fmt...) logger(LOGGER_STATUS, class, ##fmt)

/**
 * logger_binary - log binary string as hex
 * @param severity maximum severity level that causes the log entry to be logged
 * @param class logging class
 * @param bin binary string
 * @param binlen length of binary string
 * @param str string that is prepended to hex-converted binary string
 */
#define logger_binary(severity, class, bin, binlen, str)		       \
	do {                                                                   \
		_Pragma("GCC diagnostic push")                                 \
		_Pragma("GCC diagnostic ignored \"-Wpedantic\"")	       \
		_logger_binary(severity, class, bin, binlen,		       \
			       str, __FILE__, __FUNCTION__, __LINE__);	       \
		_Pragma("GCC diagnostic pop")				       \
	} while (0);

/**
 * logger - log a percentage only if LOG_NONE is given
 * @param percentage Integer indicating a percentage value
 * @param fmt format string printed during first call
 */
void logger_spinner(const unsigned int percentage, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/**
 * logger_set_verbosity - set verbosity level
 */
void logger_set_verbosity(const enum logger_verbosity level);

/**
 * logger_set_class - set logging class
 */
int logger_set_class(const enum logger_class class);

/**
 * logger_get_class - List all logging classes to file descriptor
 */
void logger_get_class(const int fd);

/**
 * logger_get_verbosity - get verbosity level for given class
 */
enum logger_verbosity logger_get_verbosity(const enum logger_class class);

/**
 * logger_inc_verbosity - increase verbosity level by one
 */
void logger_inc_verbosity(void);

/**
 * Log into the given file
 *
 * Note: The status logging will always log to stderr and will be always
 *	 active if a log file is set.
 *
 * @param pathname [in] Path name of log file
 * @return 0 on success, < 0 on error
 */
int logger_set_file(const char *pathname);

/**
 * Retrieve the file stream to log to.
 */
FILE *logger_log_stream(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
