/* List all pending request IDs
 *
 * Copyright (C) 2019, Stephan Mueller <smueller@chronox.de>
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
#include <unistd.h>

#include "acvpproxy.h"
#include "internal.h"
#include "mutex_w.h"
#include "term_colors.h"

static DEFINE_MUTEX_W_UNLOCKED(acvp_list_verdicts_mutex);

static void acvp_list_verdict_print(struct acvp_test_verdict_status *verdict)
{
	if (!verdict->verdict) {
		fprintf_blue(stdout, "UNVERIFIED\n");
		return;
	}

	switch(verdict->verdict) {
	case acvp_verdict_pass:
		fprintf_green(stdout, "PASSED\n");
		break;
	case acvp_verdict_fail:
		fprintf_red(stdout, "FAILED\n");
		break;
	case acvp_verdict_unknown:
		fprintf_blue(stdout, "UNVERIFIED\n");
		break;
	default:
		fprintf_red(stdout, "ERROR in obtaining verdict\n");
	}
}

static int acvp_list_verdicts_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				   const struct acvp_buf *buf)
{
	struct acvp_vsid_ctx tmp_ctx;
	int ret;

	(void)buf;

	memcpy(&tmp_ctx, vsid_ctx, sizeof(tmp_ctx));
	CKINT(ds->acvp_datastore_get_vsid_verdict(&tmp_ctx));

	fprintf(stdout, "\tVector set ID %u\t\t", vsid_ctx->vsid);
	acvp_list_verdict_print(&tmp_ctx.verdict);

out:
	return ret;
}

static int acvp_list_verdicts_cb(const struct acvp_ctx *ctx,
				 const struct definition *def,
				 const uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition data not defined\n");

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->testid = testid;

	mutex_w_lock(&acvp_list_verdicts_mutex);

	CKINT(ds->acvp_datastore_get_testid_verdict(testid_ctx));

	fprintf(stdout, "Test session ID %u\t\t\t", testid_ctx->testid);
	acvp_list_verdict_print(&testid_ctx->verdict);

	CKINT(ds->acvp_datastore_find_responses(testid_ctx,
						acvp_list_verdicts_vsid));

	/*
	 * We will get an EEXIST back due to the final call to
	 * acvp_datastore_find_testid_verdict in
	 * acvp_datastore_find_responses.
	 */
	ret = 0;

out:
	mutex_w_unlock(&acvp_list_verdicts_mutex);
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int acvp_list_verdicts(const struct acvp_ctx *ctx)
{
	return acvp_process_testids(ctx, &acvp_list_verdicts_cb);
}
