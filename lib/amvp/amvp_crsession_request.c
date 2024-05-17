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

#if 1
// This should come from the database - mockup code
static int amvp_result_build_mockup(struct acvp_vsid_ctx *certreq_ctx,
				    struct json_object **json_result)
{
	struct json_object *array, *entry, *array2;
	int ret;

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);

	CKINT(acvp_req_add_version(array));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(array, entry));

	CKINT(json_object_object_add(entry, "moduleId",
		json_object_new_int((int)certreq_ctx->vsid)));

	array2 = json_object_new_array();
	CKNULL(array2, -ENOMEM);
	CKINT(json_object_object_add(entry, "evidenceSet", array2));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(array2, entry));

	CKINT(json_object_object_add(entry, "testRequirement",
				     json_object_new_string("TE02.20.01")));
	CKINT(json_object_object_add(entry, "evidence",
				     json_object_new_string("foobar")));

	*json_result = array;

out:
	return ret;
}

static int amvp_upload_evidence_mockup(struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *result = NULL;
	const char *json_request;
	int ret, ret2;

	CKINT(amvp_result_build_mockup(certreq_ctx, &result));
	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));

	json_request = json_object_to_json_string_ext(
		result,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");
	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);
	ret2 = acvp_net_op(module_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(module_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

out:
	ACVP_JSON_PUT_NULL(result);
	acvp_free_buf(&response_buf);
	return ret;
}
#endif

/*
 * GET /certRequests/<ID>/evidenceSets
 */
static int amvp_evidenceset_get(struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_net_ctx *net;
	ACVP_BUFFER_INIT(response_buf);
	ACVP_BUFFER_INIT(tmp);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	//TODO: this is test code, remove once download of real evidence data is possible
	CKINT(amvp_upload_evidence_mockup(certreq_ctx));

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_EVIDENCESETS));

	ret2 = acvp_net_op(module_ctx, url, NULL, &response_buf, acvp_http_get);

	/* Initialize the vsID directory for later potential re-load. */
	CKINT(acvp_store_vector_status(
		certreq_ctx,
		"vsID HTTP GET operation completed with return code %d\n",
		ret2));

	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	/* Store the vsID data in data store */
	CKINT(ds->acvp_datastore_write_vsid(certreq_ctx,
					    datastore->amvp_evidencesetfile,
					    false, &response_buf));

	CKINT(acvp_get_net(&net));
	tmp.buf = (uint8_t *)net->server_name;
	tmp.len = (uint32_t)strlen((char *)tmp.buf);
	CKINT(ds->acvp_datastore_write_vsid(certreq_ctx, datastore->srcserver,
					    true, &tmp));

out:
	acvp_free_buf(&response_buf);
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
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	struct acvp_vsid_ctx certreq_ctx;
	char url[ACVP_NET_URL_MAXLEN];
	struct json_object *resp = NULL, *data = NULL;
	uint32_t certreq_id;
	int ret;

	/* Analyze the result */

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	CKINT(acvp_get_accesstoken(module_ctx, data, true));

	ret = acvp_meta_register_get_id(response, &certreq_id);
	if (ret == -EAGAIN || acvp_request_id(certreq_id)) {
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
	} else if (ret) {
		goto out;
	}

	//TODO: check response buffer?

	certreq_id = acvp_id(certreq_id);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained certRequest ID %u\n",
	       certreq_id);

	/* Initialize the certreq_ctx to track the certRequest */
	memset(&certreq_ctx, 0, sizeof(certreq_ctx));
	certreq_ctx.testid_ctx = module_ctx;
	certreq_ctx.vsid = certreq_id;

	/* Initialize the certRequestID directory for later potential re-load. */
	CKINT(acvp_store_vector_status(&certreq_ctx,
	      "certRequest downloading commences\n"));

	/*
	 * Caller requested the registering of the tests vector definition
	 * only without obtaining the test vectors themselves.
	 */
	if (opts->register_only) {
		logger_status(LOGGER_C_ANY, "Module session %u registered\n",
			      module_ctx->testid);
		goto out;
	}

	/*
	 * Get the evidence Set associated with the certRequest
	 */
	CKINT(amvp_evidenceset_get(&certreq_ctx));

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

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
 * GET /certRequests/<ID>
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
 * Process module response
 */
static int amvp_module_process(struct acvp_testid_ctx *module_ctx,
			       const struct acvp_buf *response, uint32_t *id)
{
	struct json_object *resp = NULL, *data = NULL;
	uint32_t tmp_id;
	int ret;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	(void)module_ctx;
	CKINT(json_get_uint(data, "id", &tmp_id));

	/* Reject a request ID */
	if (acvp_request_id(tmp_id)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Invalid request ID received from ACVP server (did the request IDs became so large that it interferes with the indicator bits?)\n");
		ret = -EFAULT;
		goto out;
	}

	tmp_id = acvp_id(tmp_id);
	*id = tmp_id;

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/* GET /modules/<id> */
static int amvp_module_get(struct acvp_testid_ctx *module_ctx,
			   uint32_t *module_id)
{
	ACVP_BUFFER_INIT(response_buf);
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	//TODO reenable once the server is fixed
	return 0;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", *module_id));

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(module_ctx, url, NULL, &response_buf,
			   acvp_http_get);

	if (ret2)
		module_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(module_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_module_process(module_ctx, &response_buf, module_id));

out:
	acvp_free_buf(&response_buf);

	return ret;
}

/*
 * Retrieve the module ID
 *
 * GET /requests/<id>
 */
static int amvp_module_get_op(struct acvp_testid_ctx *module_ctx,
			      const struct acvp_buf *response,
			      uint32_t *module_id)
{
	int ret;

	/* Analyze the result from the POST */
	ret = acvp_meta_register_get_id(response, module_id);
	if (ret == -EAGAIN)
		ret = 0;
	if (ret)
		goto out;

	if (!acvp_request_id(*module_id)) {
		CKINT(amvp_module_get(module_ctx, module_id));
		goto out;
	}

	/* Implement the waiting */
#define AMVP_GET_DATAFILE_INFO_SLEEPTIME 30
	for (;;) {
		ret = acvp_meta_obtain_request_result(module_ctx, module_id);

		/* Wait the requested amount of seconds */
		if (ret == -EAGAIN || acvp_request_id(*module_id)) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "AMVP server needs more time - sleeping for %u seconds for requestID %u again\n",
			       AMVP_GET_DATAFILE_INFO_SLEEPTIME,
			       acvp_id(*module_id));
			CKINT(sleep_interruptible(
				AMVP_GET_DATAFILE_INFO_SLEEPTIME,
				&acvp_op_interrupted));
		} else {
			break;
		}
	}

	if (!acvp_request_id(*module_id))
		CKINT(amvp_module_get(module_ctx, module_id));

out:
	return ret;
}

static int amvp_module_process_req(struct acvp_testid_ctx *module_ctx,
				   const struct acvp_buf *response)
{
	uint32_t module_id;
	int ret;

	CKINT(amvp_module_get_op(module_ctx, response, &module_id));
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained module ID %u\n",
	       module_id);

	/* The received module ID is stored for the session */
	module_ctx->testid = module_id;

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(module_ctx, AMVP_DS_MODULEIDMETA,
					      true, response));

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

/*
 * Register module definition and start a new "module session".
 *
 * The returned module ID is stored in the module_ctx as "testid"
 *
 * POST /modules
 */
static int amvp_module_register_op(struct acvp_testid_ctx *module_ctx)
{
	const struct acvp_ctx *ctx;
	const struct acvp_req_ctx *req_details;
	const struct definition *def;
	struct amvp_def *amvp;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKNULL(module_ctx, -EINVAL);

	def = module_ctx->def;
	CKNULL(def, -EINVAL);
	amvp = def->amvp;
	if (!amvp) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Skippking AMVP operation on module as it has no AMVP context\n");
		return 0;
	}

	ctx = module_ctx->ctx;
	req_details = &ctx->req_details;

	/*
	 * The module registration JWT acts as the session JWT and thus must
	 * be maintained for the session.
	 */
	CKINT_LOG(acvp_init_auth(module_ctx),
		  "Failure to initialize authtoken\n");

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				amvp->validation_definition,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));

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
		amvp->validation_definition,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(module_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	if (ret2)
		module_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(module_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	/* Process response */
	CKINT(amvp_module_process_req(module_ctx, &response_buf));

out:
	acvp_release_auth(module_ctx);
	module_ctx->server_auth = NULL;
	acvp_free_buf(&response_buf);

	return ret;
}

/* Register module definition for one given definition */
static int amvp_register_module(const struct acvp_ctx *ctx,
				const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx module_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(def, -EINVAL);

	memset(&module_ctx, 0, sizeof(module_ctx));

	CKINT(acvp_init_testid_ctx(&module_ctx, ctx, def, testid));

	CKINT(amvp_module_register_op(&module_ctx));

out:
	return ret;
}

DSO_PUBLIC
int amvp_register(struct acvp_ctx *ctx)
{
	return acvp_register_cb(ctx, &amvp_register_module);
}
