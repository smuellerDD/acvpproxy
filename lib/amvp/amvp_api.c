/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "acvpproxy.h"
#include "amvpproxy.h"
#include "amvp_internal.h"
#include "aux_helper.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "sleep.h"
#include "threading_support.h"

/******************************************************************************
 * Submission of evidence
 ******************************************************************************/
static int amvp_submit_te_evidence(const struct acvp_vsid_ctx *certreq_ctx,
				   const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
//	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
//	const struct acvp_net_ctx *net;
//	ACVP_BUFFER_INIT(tmp);
	int ret = 0;

#if 0
	CKINT(acvp_get_net(&net));

	tmp.buf = (uint8_t *)net->server_name;
	tmp.len = (uint32_t)strlen((char *)tmp.buf);
	ret = ds->acvp_datastore_compare(certreq_ctx, datastore->srcserver,
					 true, true, &tmp);
	if (ret < 0) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Could not match the upload server for vsID %u with the download server\n",
		       certreq_ctx->vsid);
		goto out;
	}
#endif

	if (!opts->fetch_status && !opts->amvp_certify) {
		/*
		 * Upload the TE report evidence.
		 */
		CKINT(amvp_te_upload_evidence(certreq_ctx, buf));
	}

out:
	return ret;
}

static int amvp_submit_evidence_once(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	int ret = 0;

	if (opts->fetch_sp) {
		CKINT(amvp_sp_get_pdf(certreq_ctx));
	} else if (opts->generate_sp) {
		CKINT(amvp_sp_gen_pdf(certreq_ctx));
	} else if (opts->amvp_certify) {
		CKINT(amvp_certify(certreq_ctx));
	} else if (opts->amvp_send_certificate_prerequisites) {
		CKINT(amvp_certrequest_prereq(certreq_ctx));
	} else if (opts->fetch_status) {
		/* do nothing */
		;
	} else {
		/*
		 * Upload the Security Policy data.
		 */
		CKINT(amvp_sp_upload_evidence(certreq_ctx));
		if (req_details->dump_register)
			goto out;
	}

out:
	return ret;
}

/******************************************************************************
 * Process handler
 ******************************************************************************/

static int amvp_process_one_certreq(const struct acvp_vsid_ctx *certreq_ctx,
				    const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	struct amvp_state *state = module_ctx->amvp_state;
	int ret;

	if (opts->fetch_status && !state->submit_once_done)
		CKINT(amvp_certrequest_status(
			certreq_ctx, amvp_certrequest_status_show_all));

	if (state->overall_state < AMVP_REQUEST_STATE_ONGOING) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Certification status does not allow pushing information - wait\n");
		ret = -EAGAIN;
		goto out;
	}

	/*
	 * Now, submit all evidence.
	 */
	CKINT(amvp_submit_te_evidence(certreq_ctx, buf));

	/*
	 * As this function can be called multiple times (once for each TE
	 * JSON file), we need a guard for data to be submitted only once.
	 */
	if (!state->submit_once_done) {
		CKINT(amvp_submit_evidence_once(certreq_ctx));
		state->submit_once_done = true;
	}

out:
	return ret;
}

static int amvp_continue_op(struct acvp_testid_ctx *testid_ctx)
{

	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	thread_set_name(acvp_testid, testid_ctx->testid);

	CKINT(acvp_init_auth(testid_ctx));

	testid_ctx->status_parse_amvp = amvp_read_status;
	testid_ctx->status_write = amvp_write_status;

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Post all available TEs */
	CKINT(ds->acvp_datastore_find_responses(testid_ctx,
						amvp_process_one_certreq));

out:
	acvp_release_auth(testid_ctx);
	return ret;
}

/******************************************************************************
 * APIs
 ******************************************************************************/

static int amvp_init_testid_ctx(struct acvp_testid_ctx *testid_ctx,
				const struct acvp_ctx *ctx,
				const struct definition *def,
				const uint64_t testid)
{
	int ret;

	CKINT(amvp_alloc_state(testid_ctx));
	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));

out:
	return ret;
}

/*
 * Query an already registered module waiting for NIST approval. Once the
 * registration is obtained, register the cert request.
 */
static int amvp_certrequest(const struct acvp_ctx *ctx,
			    const struct definition *def, uint64_t testid)
{
	struct acvp_testid_ctx module_ctx = { 0 };
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(def, -EINVAL);

	CKINT(amvp_init_testid_ctx(&module_ctx, ctx, def, testid));

	/*
	 * The module registration JWT acts as the session JWT and thus must
	 * be maintained for the session.
	 */
	CKINT_LOG(acvp_init_auth(&module_ctx),
		  "Failure to initialize authtoken\n");

	/* Now register the certRequest with the module */
	CKINT(amvp_certrequest_register(&module_ctx));

out:
	acvp_release_auth(&module_ctx);
	module_ctx.server_auth = NULL;
	amvp_release_state(&module_ctx);
	return ret;
}

/* Register module definition for one given definition */
static int _amvp_continue(const struct acvp_ctx *ctx,
			  const struct definition *def, uint64_t testid)
{
	struct acvp_testid_ctx module_ctx = { 0 };
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(def, -EINVAL);

	CKINT(amvp_init_testid_ctx(&module_ctx, ctx, def, testid));

	CKINT(amvp_continue_op(&module_ctx));

out:
	amvp_release_state(&module_ctx);
	return ret;
}

DSO_PUBLIC
int amvp_register(struct acvp_ctx *ctx)
{
	return acvp_register_cb(ctx, &amvp_certrequest);
}

DSO_PUBLIC
int amvp_continue(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx, amvp_init_testid_ctx,
				   amvp_read_status, NULL, NULL,
				   amvp_write_status));

	CKINT(acvp_process_testids(ctx, &_amvp_continue));

out:
	return ret;
}
