/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "rbg_internal.h"
#include "ret_checkers.h"

/***************************************************************************
 * RBG status handling
 ***************************************************************************/
int rbg_read_status(struct acvp_testid_ctx *testid_ctx,
		    struct json_object *status)
{
	struct rbg_def *rbg = testid_ctx->rbg_def;
	int ret;

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Parsing status of RBG\n");

	CKINT(json_get_bool(status, "esvSubmissionParallel",
			    &rbg->esv_submission));

out:
	return ret;
}

int rbg_write_status(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	struct rbg_def *rbg = testid_ctx->rbg_def;
	struct json_object *stat = NULL;
	struct acvp_buf stat_buf;
	const char *stat_str;
	int ret;

	stat = json_object_new_object();
	CKNULL(stat, -ENOMEM);

	CKINT(json_object_object_add(
		stat, "esvSubmissionParallel",
		json_object_new_boolean(rbg->esv_submission)));

	stat_str = json_object_to_json_string_ext(
		stat, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(stat_str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat_buf.buf = (uint8_t *)stat_str;
	stat_buf.len = (uint32_t)strlen(stat_str);

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(
		testid_ctx, datastore->rbg_statusfile, true, &stat_buf));

out:
	ACVP_JSON_PUT_NULL(stat);

	return ret;
}
