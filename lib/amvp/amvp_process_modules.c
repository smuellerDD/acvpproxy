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
 * Module handling
 ******************************************************************************/

/*
 * Process response from /modules/<id>
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
 * Retrieve the module ID from the module_request_id
 * The caller provides the request ID in the module_id variable. After
 * successful completion, the module_id contains the approved and valid
 * ID.
 *
 * GET /requests/<id>
 */
static int amvp_module_get_op(struct acvp_testid_ctx *module_ctx,
			      uint32_t *module_id)
{
	int ret;

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

/*
 * Process response from the module_register_op
 */
static int amvp_module_process_req(struct acvp_testid_ctx *module_ctx,
				   const struct acvp_buf *response)
{
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	uint32_t module_id;
	int ret;

	/* Analyze the result from the POST */
	ret = acvp_meta_register_get_id(response, &module_id);
	if (ret == -EAGAIN)
		ret = 0;
	if (ret)
		goto out;

	if (opts->register_only && acvp_request_id(module_id)) {
		module_id = acvp_id(module_id);

		logger_status(LOGGER_C_ANY,
			      "Module request registered with request ID %u\nHave this ID approved by NIST and continue the operation with amvp-proxy --modulereqid %u\n",
			      module_id, module_id);
		ret = 0;
		goto out;
	}

	CKINT(amvp_module_get_op(module_ctx, &module_id));
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained module ID %u\n",
	       module_id);


	/* The received module ID is stored for the session */
	module_ctx->testid = module_id;

	logger_status(LOGGER_C_ANY,
		      "Module registered with ID %u\nIf you want to manually create a (new) certificate request for this module ID use the command amvp-proxy --moduleid %u. It is permissible to have multiple certificate requests for one module. Typically, the certificate request is automatically requested after this.\n",
		      module_id, module_id);

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(module_ctx, AMVP_DS_MODULEIDMETA,
					      true, response));

	CKINT(amvp_certrequest_register(module_ctx));

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
int amvp_module_register_op(struct acvp_testid_ctx *module_ctx)
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
