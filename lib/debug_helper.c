/* ACVP debug helper
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

#include <ctype.h>
#include <string.h>
#include <stdarg.h>

#include "logger.h"
#include "internal.h"
#include "json_wrapper.h"
#include "definition.h"
#include "totp.h"

/* String must not contain characters that move in the file hierarchy */
int acvp_sanitize_string(char *string)
{
	unsigned int slen;

	if (!string)
		return 0;

	slen = strlen(string);

	while (slen) {
		if (!isalnum(*string) && *string != '_' && *string != '-')
			*string = '_';

		string++;
		slen--;
	}

	return 0;
}

int acvp_store_vector_status(const struct acvp_vsid_ctx *vsid_ctx,
			     const char *fmt, ...)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct definition *def = testid_ctx->def;
	va_list args;
	ACVP_BUFFER_INIT(tmp);
	char filename[FILENAME_MAX], msg[4096];

	if (!def)
		return 0;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	tmp.buf = (uint8_t *)msg;
	tmp.len = strlen(msg);

	snprintf(filename, sizeof(filename), "%s.status",
		 datastore->vectorfile);

	return ds->acvp_datastore_write_vsid(vsid_ctx, filename, false, &tmp);
}

int acvp_store_vector_debug(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct definition *def = testid_ctx->def;
	char filename[FILENAME_MAX];

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	snprintf(filename, sizeof(filename), "%s.debug", datastore->vectorfile);

	return ds->acvp_datastore_write_vsid(vsid_ctx, filename, true, buf);
}

int acvp_store_verdict_debug(const struct acvp_vsid_ctx *vsid_ctx,
			     const struct acvp_buf *buf, int err)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct definition *def = testid_ctx->def;
	char filename[FILENAME_MAX];

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	snprintf(filename, sizeof(filename), "%s.debug",
		 datastore->verdictfile);

	return ds->acvp_datastore_write_vsid(vsid_ctx, filename, true, buf);
}

int acvp_store_submit_debug(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct definition *def;

	if (!testid_ctx)
		return 0;

	def = testid_ctx->def;
	if (!def)
		return 0;

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	return ds->acvp_datastore_write_vsid(vsid_ctx,
					     "result_submit_response.debug",
					     true, buf);
}

static int acvp_store_timed_pathname(const char *filenamepart, char *filename,
			      size_t filenamelen)
{
	struct tm now_detail;
	time_t now;

	/* Create processed file */
	now = time(NULL);
	if (now == (time_t)-1) {
		int ret = -errno;

		logger(LOGGER_WARN, LOGGER_C_ANY, "Cannot obtain local time\n");
		return ret;
	}
	localtime_r(&now, &now_detail);

	snprintf(filename, filenamelen,
		 "%s-%d%.2d%.2d_%.2d-%.2d-%.2d.debug",
		 filenamepart,
		 now_detail.tm_year + 1900,
		 now_detail.tm_mon + 1,
		 now_detail.tm_mday,
		 now_detail.tm_hour,
		 now_detail.tm_min,
		 now_detail.tm_sec);

	return 0;
}

static int _acvp_store_timed_debug(const struct acvp_testid_ctx *testid_ctx,
				   const struct acvp_buf *buf,
				   const char *filenamepart, int err)
{
	const struct definition *def = testid_ctx->def;
	char filename[100];
	int ret = 0;

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	CKINT(acvp_store_timed_pathname(filenamepart, filename,
					sizeof(filename)));

	return ds->acvp_datastore_write_testid(testid_ctx, filename, true,
					       buf);

out:
	return ret;
}

int acvp_store_login_debug(const struct acvp_testid_ctx *testid_ctx,
			   const struct acvp_buf *buf, int err)
{
	return _acvp_store_timed_debug(testid_ctx, buf, "login_response",
				       err);
}

int acvp_store_register_debug(const struct acvp_testid_ctx *testid_ctx,
			      const struct acvp_buf *buf,
			      int err)
{
	return _acvp_store_timed_debug(testid_ctx, buf, "register_response",
				       err);
}

int acvp_store_vector_request_debug(const struct acvp_testid_ctx *testid_ctx,
				    const struct acvp_buf *buf, int err)
{
	return _acvp_store_timed_debug(testid_ctx, buf,
				       "vector_request_response", err);
}

int acvp_store_vendor_debug(const struct acvp_testid_ctx *testid_ctx,
			    const struct acvp_buf *buf, int err)
{
	const struct definition *def = testid_ctx->def;

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	return ds->acvp_datastore_write_testid(testid_ctx, "vendor.debug",
					       true, buf);
}

int acvp_store_oe_debug(const struct acvp_testid_ctx *testid_ctx,
			const struct acvp_buf *buf, int err)
{
	const struct definition *def = testid_ctx->def;

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	return ds->acvp_datastore_write_testid(testid_ctx, "oe.debug",
					       true, buf);
}

int acvp_store_module_debug(const struct acvp_testid_ctx *testid_ctx,
			    const struct acvp_buf *buf, int err)
{
	const struct definition *def = testid_ctx->def;

	if (!err && logger_get_verbosity(LOGGER_C_ANY) < LOGGER_DEBUG)
		return 0;

	if (!def)
		return 0;

	return ds->acvp_datastore_write_testid(testid_ctx, "module.debug",
					       true, buf);
}
