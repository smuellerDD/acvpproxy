/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * certRequest handling
 ******************************************************************************/

/*
 * Get the template data for certificate request.
 */
static int amvp_certrequest_req(struct acvp_testid_ctx *module_ctx,
				uint32_t certreq_id)
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

	logger_status(LOGGER_C_ANY,
		      "Now, edit the TE evidence data as well as the SP in the data directory for certificate request %u.\nOnce completed, invoke amvp-proxy --vsid %u to submit the data\n",
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
	uint32_t certreq_id;
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
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained certRequest ID %u\n",
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
	if (!json_object_is_type(amvp->registration_definition,
				 json_type_array) &&
	    json_object_array_length(amvp->registration_definition) < 2) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unexpected JSON format\n");
		ret = -EINVAL;
		goto out;
	}

	data = json_object_array_get_idx(amvp->registration_definition, 1);

	CKINT(json_object_object_add(data, "moduleId",
		json_object_new_int((int)module_ctx->testid)));

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
		       "To register a certificate request, you must have a valid module ID. Currently only a module request ID is available. Process it with --modulereqid %u\n",
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
