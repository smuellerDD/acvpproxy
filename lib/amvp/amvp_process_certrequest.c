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
#include "term_colors.h"
#include "threading_support.h"

/******************************************************************************
 * certRequest status processing
 ******************************************************************************/

static int amvp_certrequest_status_check(struct json_object *data,
					 unsigned int *status,
					 const char *key)
{
	const char *str;
	int ret;

	*status = 0;

	/* Get the status */
	CKINT(json_get_string(data, key, &str));
	if (!strncasecmp(str, "initial", 7)) {
		logger_status(LOGGER_C_ANY,
			      "%sProcessing (%s) initial - not all evidence submitted%s\n",
			      TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_INITIAL;
	} else if (!strncasecmp(str, "ready", 5)) {
		logger_status(LOGGER_C_ANY,
			      "%sProcessing (%s) ongoing - not all evidence submitted%s\n",
			      TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_ONGOING;
	} else if (!strncasecmp(str, "requirementsSubmitted", 21)) {
		logger_status(LOGGER_C_ANY,
			      "%sOverall processing (%s) completed%s\n",
			      TERM_COLOR_GREEN_INVERTED, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_COMPLETED;
	} else if (!strncasecmp(str, "submitted", 9)) {
		logger_status(LOGGER_C_ANY, "%sProcessing (%s) completed%s\n",
			      TERM_COLOR_GREEN, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_COMPLETED;
	} else if (!strncasecmp(str, "pendingGeneration", 17)) {
		logger_status(LOGGER_C_ANY, "%sPending generation (%s)%s\n",
			      TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_PENDING_GENERATION;
	} else if (!strncasecmp(str, "processing", 10)) {
		logger_status(LOGGER_C_ANY,
			      "%sAMVP server processes request (%s)%s\n",
			      TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_PENDING_PROCESSING;
	} else if (!strncasecmp(str, "approved", 8)) {
		const char *str2;

		CKINT(json_get_string(data, "validationCertificate", &str2));
		logger_status(LOGGER_C_ANY,
			      "%sAMVP Processing completed - certificate %s awarded%s\n",
			      TERM_COLOR_GREEN_INVERTED, str2, TERM_COLOR_NORMAL);

		*status = AMVP_REQUEST_STATE_APPROVED;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown overall status %s for key %s\n", str, key);
		ret = -ENOENT;
	}

out:
	return ret;
}

/*
 * Process certificate request status
 */
int _amvp_certrequest_status(const struct acvp_vsid_ctx *certreq_ctx,
			     const struct acvp_buf *response)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	struct amvp_state *state = module_ctx->amvp_state;
	struct json_object *resp = NULL, *data = NULL;
	int ret;

	/* Analyze the result */
	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	/* Overall status */
	CKINT(amvp_certrequest_status_check(data, &state->overall_state,
					    "status"));

	/* In the initial state we do not have additional states */
	if (state->overall_state == AMVP_REQUEST_STATE_INITIAL)
		goto out;

	/*
	 * If the status is approved, we are certified and do not need to
	 * consider other status information.
	 */
	if (state->overall_state == AMVP_REQUEST_STATE_APPROVED) {
		/* Store the entire received response. */
		const char *str;

		CKINT(json_get_string(data, "validationCertificate", &str));

		strncpy(state->certificate, str, sizeof(state->certificate));

		logger_status(LOGGER_C_ANY,
			      "%sCertificate received for certification request ID %"PRIu64": %s%s\n",
			      TERM_COLOR_GREEN_INVERTED, certreq_ctx->vsid,
			      state->certificate, TERM_COLOR_NORMAL);

		/*
		 * TODO: is the AMVP certificate a module-global state or
		 * certificate request ID-local - for now we err on the safe
		 * side by storing it as certificate request local.
		 */
		//CKINT(acvp_store_file(module_ctx, response, 1,
		//		      datastore->testsession_certificate_info));

		CKINT(ds->acvp_datastore_write_vsid(
			certreq_ctx, datastore->verdictfile, false, response));
		goto out;
	}

	/*
	 * SP status
	 *
	 * First check for the status which is only present if all is submitted.
	 * If it is not present, check for the individual SP sections.
	 */
	ret = amvp_certrequest_status_check(data, &state->sp_state,
					    "securityPolicyStatus");
	if (ret == -ENOENT) {
		CKINT(amvp_sp_status(certreq_ctx, data));
	} else if (ret) {
		goto out;
	}

	/*
	 * FT-TE status
	 *
	 * First check for the status which is only present if all is submitted.
	 * If it is not present, check for the individual FT TE sections.
	 */
	ret = amvp_certrequest_status_check(data, &state->ft_te_state,
					    "functionalTestStatus");
	if (ret == -ENOENT) {
		CKINT(amvp_ft_te_status(certreq_ctx, data));
	} else if (ret) {
		goto out;
	}

	/*
	 * SC-TE status
	 *
	 * First check for the status which is only present if all is submitted.
	 * If it is not present, check for the individual SC TE sections.
	 */
	ret = amvp_certrequest_status_check(data, &state->sc_te_state,
					    "sourceCodeStatus");
	if (ret == -ENOENT) {
		CKINT(amvp_sc_te_status(certreq_ctx, data));
	} else if (ret) {
		goto out;
	}

out:
	if (!ret)
		ret = amvp_write_status(module_ctx);

	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/*
 * GET /certRequests/<id>
 */
int amvp_certrequest_status(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_BUFFER_INIT(response);
	int ret, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
				  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));

	ret2 = acvp_net_op(module_ctx, url, NULL, &response, acvp_http_get);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	/* Analyze the result */
	CKINT(_amvp_certrequest_status(certreq_ctx, &response))

out:
	acvp_free_buf(&response);
	return ret;
}


/******************************************************************************
 * certRequest handling
 ******************************************************************************/

/*
 * Get the template data for certificate request.
 */
static int amvp_certrequest_req(struct acvp_testid_ctx *module_ctx,
				uint64_t certreq_id)
{
	struct acvp_vsid_ctx certreq_ctx;
	int ret;

	/* Initialize the certreq_ctx to track the certRequest */
	memset(&certreq_ctx, 0, sizeof(certreq_ctx));
	certreq_ctx.testid_ctx = module_ctx;
	certreq_ctx.vsid = certreq_id;

	/* Initialize the certRequestID directory for later potential re-load. */
	CKINT(acvp_store_vector_status(&certreq_ctx,
	      "certRequest downloading commences\n"));

	/*
	 * Get the TE Template data.
	 */
	CKINT(amvp_te_get(&certreq_ctx));

	/*
	 * Get the status
	 */
	CKINT(amvp_certrequest_status(&certreq_ctx));

	logger_status(LOGGER_C_ANY,
		      "Now, edit the TE evidence data as well as the SP in the data directory for certificate request %"PRIu64".\nOnce completed, invoke amvp-proxy --vsid %"PRIu64" to submit the data\n",
		      certreq_id, certreq_id);

out:
	return ret;
}

/*
 * Process the certRequest response
 *
 * The response returns the certRequest ID which is further processed
 * as "vsID". This means that this function initializes the certreq_ctx which
 * is used to track the certRequest.
 */
static int amvp_certrequest_process_req(struct acvp_testid_ctx *module_ctx,
					struct acvp_buf *response)
{
	struct json_object *resp = NULL, *data = NULL;
	uint64_t certreq_id;
	int ret;

	/* Analyze the result */

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	CKINT(acvp_get_accesstoken(module_ctx, data, true));

	ret = acvp_meta_register_get_id(response, &certreq_id);

#if 0
	if (ret == -EAGAIN || acvp_request_id(certreq_id)) {
		char url[ACVP_NET_URL_MAXLEN];

		/* Wait and fetch data */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "CertRequestId pending, retrying\n");

		acvp_free_buf(response);
		CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url,
					  sizeof(url)),
			  "Creation of request URL failed\n");
		CKINT(acvp_extend_string(url, sizeof(url), "/%u",
					 acvp_id(certreq_id)));
		CKINT(acvp_process_retry_testid(module_ctx, response, url));

		/* Get the ID now after finishing waiting */
		CKINT(acvp_meta_register_get_id(response, &certreq_id));
	} else
#else
	if (ret == -EAGAIN) {
		ret = 0;
	} else
#endif

	if (ret) {
		goto out;
	}

	certreq_id = acvp_id(certreq_id);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained certRequest ID %"PRIu64"\n",
	       certreq_id);

	CKINT(amvp_certrequest_req(module_ctx, certreq_id));

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/* Build the JSON structure for the certRequest registration */
static int amvp_certrequest_build(struct acvp_testid_ctx *module_ctx)
{
	const struct definition *def;
	struct amvp_def *amvp;
	struct json_object *data;
	int ret;

	CKNULL(module_ctx, -EINVAL);

	def = module_ctx->def;
	CKNULL(def, -EINVAL);
	amvp = def->amvp;
	CKNULL(amvp, -EINVAL);

	/*
	 * Obtain the reference to the data part (i.e. skip the version
	 * header).
	 */
	if (json_object_is_type(amvp->registration_definition,
				json_type_array)) {
		if (json_object_array_length(amvp->registration_definition) < 2) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unexpected JSON format\n");
			ret = -EINVAL;
			goto out;
		}
		data = json_object_array_get_idx(amvp->registration_definition,
						 1);
	} else {
		data = amvp->registration_definition;
	}

	CKINT(json_object_object_add(data, "moduleId",
		json_object_new_int((int)module_ctx->testid)));

	// TODO: add array with algo certs: "algorithmCertificates”: [“A1”],

	// TODO: add array with ESV certs “entropyCertificates”: [“E1”]

out:
	return ret;
}

/*
 * Create a new certificate request session
 *
 * POST /certRequests
 */
static int amvp_certrequest_register_op(struct acvp_testid_ctx *module_ctx)
{
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct definition *def;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct amvp_def *amvp;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *result = NULL;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	def = module_ctx->def;
	CKNULL(def, -EINVAL);
	amvp = def->amvp;
	CKNULL(amvp, -EINVAL);

	/* Build the register information */
	CKINT(amvp_certrequest_build(module_ctx));

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				amvp->registration_definition,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		amvp->registration_definition,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(module_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	if (ret2)
		module_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(module_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_certrequest_process_req(module_ctx, &response_buf));

out:
	module_ctx->server_auth = NULL;
	acvp_free_buf(&response_buf);

	ACVP_JSON_PUT_NULL(result);

	return ret;
}

/*
 * Register a certificate request for a given module
 */
int amvp_certrequest_register(struct acvp_testid_ctx *module_ctx)
{
	int ret;

	if (!module_ctx->testid) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "To register a certificate request, you must have a valid module ID. This can only be obtained with an inital registration of a module\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (acvp_request_id(module_ctx->testid)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "To register a certificate request, you must have a valid module ID. Currently only a module request ID is available. Process it with --modulereqid %"PRIu64"\n",
		       acvp_id(module_ctx->testid));
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* Store the definition search criteria */
	CKINT_LOG(acvp_export_def_search(module_ctx),
		  "Cannot store the search criteria\n");

	/* Fetch access token - we have none at this point */
	//CKINT(acvp_get_accesstoken(module_ctx, data, true));

	/* Register the certRequest and fetch all data from the cert request */
	CKINT(amvp_certrequest_register_op(module_ctx));

out:
	return ret;
}
