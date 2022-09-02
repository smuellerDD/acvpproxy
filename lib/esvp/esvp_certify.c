/* Perform ESVP certification operation
 *
 * Copyright (C) 2021 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include "esvp_internal.h"
#include "json_wrapper.h"
#include "request_helper.h"

/******************************************************************************
 * Certification support
 ******************************************************************************/
static int esvp_certify_build(const struct acvp_testid_ctx *testid_ctx,
			      struct json_object *certify)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	const struct esvp_es_def *es = testid_ctx->es_def;
	const struct definition *def;
	struct acvp_auth_ctx *auth;
	struct def_info *def_info;
	struct def_vendor *def_vendor;
	struct def_oe *def_oe;
	struct json_object *certdata, *ea_array, *ea_entry;
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL, "ES building: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL, "ES building: cipher definitions missing\n");
	def_info = def->info;
	CKNULL_LOG(def_info, -EINVAL,
		   "ES building: module definitions missing\n");
	def_vendor = def->vendor;
	CKNULL_LOG(def_vendor, -EINVAL,
		   "ES building: vendor definitions missing\n");
	def_oe = def->oe;
	CKNULL_LOG(def_oe, -EINVAL, "ES building: OE definitions missing\n");

	/* Array entry for version */
	CKINT(acvp_req_add_version(certify));

	/* Array entry for request */
	certdata = json_object_new_object();
	CKNULL(certdata, -ENOMEM);
	CKINT(json_object_array_add(certify, certdata));

	CKINT(json_object_object_add(certdata, "itar",
				     json_object_new_boolean(es->itar)));
	CKINT(json_object_object_add(certdata,
				     "limitEntropyAssessmentToSingleModule",
				     json_object_new_boolean(false)));

	CKINT(acvp_def_get_vendor_id(def_vendor));
	ret = acvp_meta_obtain_request_result(testid_ctx,
					      &def_vendor->acvp_vendor_id);
	if (ret < 0)
		goto unlock_vendor;

	ret = acvp_def_get_oe_id(def_oe);
	if (ret < 0)
		goto unlock_vendor;
	ret = acvp_meta_obtain_request_result(testid_ctx, &def_oe->acvp_oe_id);
	if (ret < 0)
		goto unlock_oe;

	/* Lock def_info */
	ret = acvp_def_get_module_id(def_info);
	if (ret < 0)
		goto unlock_oe;

	/* Check if we have an outstanding request */
	CKINT_ULCK(acvp_meta_obtain_request_result(testid_ctx,
						   &def_info->acvp_module_id));

	if (!acvp_valid_id(def_vendor->acvp_vendor_id) ||
	    !acvp_valid_id(def_oe->acvp_oe_id) ||
	    !acvp_valid_id(def_info->acvp_module_id)) {
		logger(req_details->dump_register ? LOGGER_WARN : LOGGER_ERR,
		       LOGGER_C_ANY,
		       "Module handling: vendor / OE / module ID missing\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT_ULCK(json_object_object_add(
		certdata, "entropyId",
		json_object_new_string(es->lab_test_id)));
	CKINT_ULCK(json_object_object_add(
		certdata, "moduleId",
		json_object_new_int((int)def_info->acvp_module_id)));
	CKINT_ULCK(json_object_object_add(
		certdata, "vendorId",
		json_object_new_int((int)def_vendor->acvp_vendor_id)));

	CKINT_ULCK(esvp_build_sd(testid_ctx, certdata, false));

	ea_array = json_object_new_array();
	CKNULL(ea_array, -ENOMEM);
	CKINT(json_object_object_add(certdata, "entropyAssessments", ea_array));

	auth = es->es_auth;
	ea_entry = json_object_new_object();
	CKNULL(ea_entry, -ENOMEM);
	CKINT(json_object_array_add(ea_array, ea_entry));
	CKINT(json_object_object_add(
		ea_entry, "eaId",
		json_object_new_int((int)testid_ctx->testid)));
	CKINT(json_object_object_add(
		ea_entry, "oeId",
		json_object_new_int((int)def_oe->acvp_oe_id)));
	CKINT(json_object_object_add(ea_entry, "accessToken",
				     json_object_new_string(auth->jwt_token)));

unlock:
	ret |= acvp_def_put_module_id(def_info);
unlock_oe:
	ret |= acvp_def_put_oe_id(def_oe);
unlock_vendor:
	ret |= acvp_def_put_vendor_id(def_vendor);
out:
	return ret;
}

static int
esvp_process_certify(const struct acvp_testid_ctx *testid_ctx,
		     const struct acvp_buf *response)
{
	struct json_object *req = NULL, *entry = NULL;
	const char *str;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "No response data found\n");
		return -EFAULT;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find ESVP response\n");

	CKINT(acvp_store_file(testid_ctx, response, 1,
			      "certify-response.json"));

	CKINT(json_get_string(entry, "status", &str));
	if (!strncmp(str, "received", 8)) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server accepted certificate request - notify NIST to approve ID %u\n",
			      testid_ctx->testid);
		ret = 0;
		goto out;
	} else {
		logger_status(LOGGER_C_ANY,
			      "ESVP server certificate request status unexpected: %s\n",
			      str);
		ret = -EFAULT;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

/* POST /certify */
int esvp_certify(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	const struct acvp_req_ctx *req_details;
	struct json_object *certify = NULL;
	ACVP_EXT_BUFFER_INIT(submit);
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	const char *json_request;
	int ret, ret2;

	CKNULL(ctx, -EFAULT);

	if (!opts->esv_certify) {
		logger_status(LOGGER_C_ANY,
			      "Certify operation skipped, use --testid %u --publish to certify current request\n",
			      testid_ctx->testid);
		return 0;
	}

	req_details = &ctx->req_details;

	certify = json_object_new_array();
	CKNULL(certify, -ENOMEM);

	CKINT(esvp_certify_build(testid_ctx, certify));

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

	/* Send the data to the ESVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &submit, &response, acvp_http_post);

	CKINT(acvp_request_error_handler(ret2));

	CKINT(esvp_write_status(testid_ctx));
	CKINT(esvp_process_certify(testid_ctx, &response));

out:
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(certify);
	return ret;
}
