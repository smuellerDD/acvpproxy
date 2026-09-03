/* Perform RBG certification operation
 *
 * Copyright (C) 2026, Joachim Vandersmissen <joachim@atsec.com>
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

#include "rbg_internal.h"
#include "hash/sha256.h"
#include "json_wrapper.h"
#include "request_helper.h"

#include "../esvp/esvp_internal.h"

/******************************************************************************
 * Certification support
 ******************************************************************************/
static int rbg_certify_build(const struct acvp_testid_ctx *testid_ctx,
			     struct json_object *certify)
{
	const struct rbg_def *rbg;
	const struct definition *def;
	struct def_info *def_info;
	struct json_object *certdata, *rbg_entry = NULL, *sd_array = NULL;
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL, "RBG building: testid_ctx missing\n");
	rbg = testid_ctx->rbg_def;
	CKNULL_LOG(rbg, -EINVAL, "RBG building: RBG information missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL, "RBG building: cipher definitions missing\n");
	def_info = def->info;
	CKNULL_LOG(def_info, -EINVAL,
		   "RBG building: module definitions missing\n");

	/* Array entry for version */
	CKINT(acvp_req_add_version(certify));

	/* Array entry for request */
	certdata = json_object_new_object();
	CKNULL(certdata, -ENOMEM);
	CKINT(json_object_array_add(certify, certdata));

	/* Lock def_info */
	ret = acvp_def_get_module_id(def_info);
	if (ret < 0)
		goto out;

	CKINT_ULCK(json_object_object_add(certdata, "moduleId",
		    json_object_new_int((int)def_info->acvp_module_id)));
	CKINT_ULCK(json_object_object_add(certdata, "entropyId",
		   json_object_new_string("E123"))); // TODO: use rbg->lab_test_id

	struct acvp_auth_ctx *auth = rbg->rbg_auth;

	rbg_entry = json_object_new_object();
	CKNULL(rbg_entry, -ENOMEM);
	CKINT(json_object_object_add(certdata, "rbg", rbg_entry));
	CKINT(json_object_object_add(
		rbg_entry, "rbgId",
		json_object_new_int((int)testid_ctx->testid)));
	CKINT(json_object_object_add(rbg_entry, "accessToken",
		json_object_new_string(auth->jwt_token)));

	sd_array = json_object_new_array();
	CKNULL(sd_array, -ENOMEM);
	CKINT(json_object_object_add(certdata, "supportingDocumentation",
				     sd_array));

	esvp_build_sd(rbg->sd, sd_array, false);

unlock:
	ret |= acvp_def_put_module_id(def_info);
out:
	return ret;
}

/* POST /certify/rbg */
static int rbg_certify_internal(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts;
	const struct acvp_req_ctx *req_details;
	struct json_object *certify = NULL;
	ACVP_EXT_BUFFER_INIT(submit);
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	const char *json_request;
	int ret, ret2;

	CKNULL(ctx, -EFAULT);
	opts = &ctx->options;

	if (!opts->esv_certify) {
		logger_status(LOGGER_C_ANY,
			      "Certify operation skipped - to certify this one test session, use --testid %"PRIu64" --publish to certify current request\n",
			      testid_ctx->testid);
		return 0;
	}

	req_details = &ctx->req_details;

	certify = json_object_new_array();
	CKNULL(certify, -ENOMEM);

	CKINT(rbg_certify_build(testid_ctx, certify));

	if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG &&
	    !req_details->dump_register) {
		fprintf(stdout, "Certify request with:\n%s\n",
			json_object_to_json_string_ext(
				certify, JSON_C_TO_STRING_PRETTY |
					       JSON_C_TO_STRING_NOSLASHESCAPE));
	}

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				certify,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		certify,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	submit.buf = (uint8_t *)json_request;
	submit.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_CERTIFY, url, sizeof(url)),
		  "Creation of request URL failed\n");

	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				    NIST_ESVP_VAL_OP_RBG));

	/* Send the data to the ESVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &submit, &response, acvp_http_post);

	CKINT(acvp_request_error_handler(ret2));

	CKINT(rbg_write_status(testid_ctx));
	CKINT(esvp_process_certify(testid_ctx, &response));

out:
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(certify);
	return ret;
}

/*
 * Certify a completed session
 */
int rbg_certify(struct acvp_testid_ctx *testid_ctx)
{

	return rbg_certify_internal(testid_ctx);
}
