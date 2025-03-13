/* Reading and writing of AMVP status information for re-entrant support
 *
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "base64.h"
#include "amvp_internal.h"
#include "json_wrapper.h"

void amvp_release_state(struct acvp_testid_ctx *testid_ctx)
{
	struct amvp_state *state;
	unsigned int i;

	if (!testid_ctx)
		return;

	state = testid_ctx->amvp_state;

	if (!state)
		return;

	for (i = 0; i < AMVP_SP_LAST_CHAPTER; i++) {
		if (state->sp_chapter_hash[i]) {
			free(state->sp_chapter_hash[i]);
			state->sp_chapter_hash[i] = NULL;
		}
	}

	free(testid_ctx->amvp_state);
	testid_ctx->amvp_state = NULL;
}

int amvp_alloc_state(struct acvp_testid_ctx *testid_ctx)
{
	int ret = 0;

	CKNULL(testid_ctx, -EINVAL);
	if (testid_ctx->amvp_state)
		return 0;

	testid_ctx->amvp_state = calloc(1, sizeof(struct amvp_state));
	CKNULL(testid_ctx->amvp_state, -ENOMEM);

out:
	return ret;
}

static void amvp_chapter_name(char *string, size_t stringlen,
			      unsigned int chapter)
{
	/* Add a +1 to the chapter to make it nicer in the status */
	snprintf(string, stringlen, "sp_hash_chapter_%u", chapter + 1);
}

static int amvp_read_sp_hash(struct amvp_state *state,
			     struct json_object *status, unsigned int chapter)
{
	const char *hash;
	char str [30];
	size_t len;
	int ret;

	amvp_chapter_name(str, sizeof(str), chapter);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Parsing SP chapter hash for %s\n",
	       str);
	ret = json_get_string(status, str, &hash);
	if (ret) {
		/* Allow this string to not exist */
		ret = 0;
		goto out;
	}

	if (state->sp_chapter_hash[chapter]) {
		free(state->sp_chapter_hash[chapter]);
		state->sp_chapter_hash[chapter] = NULL;
	}

	CKINT(base64_decode(hash, strlen(hash),
			    &state->sp_chapter_hash[chapter], &len));

out:
	return ret;
}

int amvp_read_status(struct acvp_testid_ctx *testid_ctx,
		     struct json_object *status)
{
	struct amvp_state *state;
	unsigned int i;
	int ret;

	CKNULL(testid_ctx, -EINVAL);
	CKNULL(status, -EINVAL);

	CKINT(amvp_alloc_state(testid_ctx));

	state = testid_ctx->amvp_state;

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Parsing status of AMVP\n");
	CKINT(json_get_bool(status, "testReportTemplateFetched",
			    &state->test_report_template_fetched));
	CKINT(json_get_uint(status, "amvpOverallRequestState",
			    &state->overall_state));
	CKINT(json_get_uint(status, "amvpSpRequestState",
			    &state->sp_state));
	CKINT(json_get_uint(status, "amvpFtTeRequestState",
			    &state->ft_te_state));
	CKINT(json_get_uint(status, "amvpScTeRequestState",
			    &state->sc_te_state));

	for (i = 0; i < AMVP_SP_LAST_CHAPTER; i++)
		CKINT(amvp_read_sp_hash(state, status, i));

out:
	return ret;
}

static int amvp_write_sp_hash(const struct amvp_state *state,
			      struct json_object *status, unsigned int chapter)
{
	char str [30], *base64_data;
	size_t base64_data_len;
	int ret;

	/* If we have no state, ignore */
	if (!state->sp_chapter_hash[chapter])
		return 0;

	amvp_chapter_name(str, sizeof(str), chapter);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Writing SP chapter hash for %s\n",
	       str);

	CKINT(base64_encode(state->sp_chapter_hash[chapter], AMVP_SP_HASH_SIZE,
			    &base64_data, &base64_data_len));

	CKINT(json_object_object_add(status, str,
				     json_object_new_string(base64_data)));

out:
	return ret;
}

int amvp_write_status(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx;
	const struct acvp_datastore_ctx *datastore;
	const struct amvp_state *state;
	struct json_object *stat = NULL;
	struct acvp_buf stat_buf;
	const char *stat_str;
	unsigned int i;
	int ret;

	CKNULL(testid_ctx, -EINVAL);
	ctx = testid_ctx->ctx;
	CKNULL(ctx, -EINVAL);
	datastore = &ctx->datastore;
	state = testid_ctx->amvp_state;
	/* Do not try to write if we have no state */
	CKNULL(state, 0);

	stat = json_object_new_object();
	CKNULL(stat, -ENOMEM);

	CKINT(json_object_object_add(
		stat, "testReportTemplateFetched",
		json_object_new_boolean(state->test_report_template_fetched)));
	CKINT(json_object_object_add(
		stat, "amvpOverallRequestState",
		json_object_new_int((int)state->overall_state)));
	CKINT(json_object_object_add(
		stat, "amvpSpRequestState",
		json_object_new_int((int)state->sp_state)));
	CKINT(json_object_object_add(
		stat, "amvpFtTeRequestState",
		json_object_new_int((int)state->ft_te_state)));
	CKINT(json_object_object_add(
		stat, "amvpScTeRequestState",
		json_object_new_int((int)state->sc_te_state)));

	for (i = 0; i < AMVP_SP_LAST_CHAPTER; i++)
		CKINT(amvp_write_sp_hash(state, stat, i));

	stat_str = json_object_to_json_string_ext(
		stat, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(stat_str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat_buf.buf = (uint8_t *)stat_str;
	stat_buf.len = (uint32_t)strlen(stat_str);

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(
		testid_ctx, datastore->amvp_statusfile, true, &stat_buf));

out:
	ACVP_JSON_PUT_NULL(stat);

	return ret;
}
