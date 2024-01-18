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
#include "aux_helper.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "sleep.h"

struct amvp_build_data {
	struct json_object *acvp_array, *esvp_array, *module_array;
};

/*
 * TOOD: use acvp_meta_register_get_id
 *
 * ISSUES:
 *	uses ID and not url
 * 	uses Initial instead of initial
 *	implements acvp_get_accesstoken as module registration returns new JWT
 */
static int amvp_certrequest_process(const struct acvp_buf *response,
				    uint32_t *id)
{
	struct json_object *resp = NULL, *data = NULL;
	uint32_t status_flag = 0, tmp_id;
	int ret;
	const char *status;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	/*
	 * {
	 *	"url": "/acvp/v1/requests/2",
	 *	"status": "approved",
	 *	"approvedUrl" : "/acvp/v1/vendors/2"
	 * }
	 */

	CKINT(json_get_string(data, "status", &status));
	if (!strncmp(status, "approved", 8)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates successful opoeration: %s\n",
		       status);
	} else if (!strncmp(status, "initial", 7) ||
		//TODO remove
		   !strncmp(status, "Initial", 7)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates initial request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_INITIAL;
	} else if (!strncmp(status, "processing", 10)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_PROCESSING;
	} else if (!strncmp(status, "rejected", 10)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates rejection of request: %s - Request information discarded locally to allow re-trying of publication.\n",
		       status);
		/*
		 * Set the ID to zero to allow performing a complete new
		 * publication operation. Yet, we throw an error to allow
		 * the user to know about the issue.
		 */
		ret = -EPERM;
		*id = 0;
		goto out;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates unsuccessful operation: %s\n",
		       status);
		ret = -EOPNOTSUPP;
		goto out;
	}

	CKINT(json_get_uint(data, "id", &tmp_id));

	/* Reject a request ID */
	if (acvp_request_id(tmp_id)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Invalid request ID received from ACVP server (did the request IDs became so large that it interferes with the indicator bits?)\n");
		ret = -EFAULT;
		goto out;
	}

	tmp_id = acvp_id(tmp_id);
	tmp_id |= status_flag;

	*id = tmp_id;

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/*
 * TOOD: use acvp_meta_register_get_id
 *
 * ISSUES:
 *	uses ID and not url
 * 	uses Initial instead of initial
 *	implements acvp_get_accesstoken as module registration returns new JWT
 */
static int amvp_module_process(struct acvp_testid_ctx *testid_ctx,
			       const struct acvp_buf *response, uint32_t *id)
{
	struct json_object *resp = NULL, *data = NULL;
	uint32_t status_flag = 0, tmp_id;
	int ret;
//	const char *status;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	(void)testid_ctx;
//	CKINT(acvp_get_accesstoken(testid_ctx, data, false));

	/*
	 * {
	 *	"url": "/acvp/v1/requests/2",
	 *	"status": "approved",
	 *	"approvedUrl" : "/acvp/v1/vendors/2"
	 * }
	 */
#if 0
	CKINT(json_get_string(data, "status", &status));
	if (!strncmp(status, "approved", 8)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates successful opoeration: %s\n",
		       status);
	} else if (!strncmp(status, "Initial", 7)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates initial request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_INITIAL;
	} else if (!strncmp(status, "processing", 10)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_PROCESSING;
	} else if (!strncmp(status, "rejected", 10)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates rejection of request: %s - Request information discarded locally to allow re-trying of publication.\n",
		       status);
		/*
		 * Set the ID to zero to allow performing a complete new
		 * publication operation. Yet, we throw an error to allow
		 * the user to know about the issue.
		 */
		ret = -EPERM;
		*id = 0;
		goto out;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates unsuccessful operation: %s\n",
		       status);
		ret = -EOPNOTSUPP;
		goto out;
	}
#endif
	CKINT(json_get_uint(data, "id", &tmp_id));

	/* Reject a request ID */
	if (acvp_request_id(tmp_id)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Invalid request ID received from ACVP server (did the request IDs became so large that it interferes with the indicator bits?)\n");
		ret = -EFAULT;
		goto out;
	}

	tmp_id = acvp_id(tmp_id);
	if (0)
		tmp_id |= status_flag;

	*id = tmp_id;

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

// This should come from the database - mockup code
static int amvp_result_build(struct acvp_testid_ctx *testid_ctx,
			     uint32_t module_id,
			     struct json_object **json_result)
{
	struct json_object *array, *entry, *array2;
	int ret;

	(void)testid_ctx;

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);

	CKINT(acvp_req_add_version(array));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(array, entry));

	CKINT(json_object_object_add(entry, "moduleId",
				     json_object_new_int((int)module_id)));

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

/* GET /certRequests/<ID> */
static int amvp_certrequest_get(struct acvp_testid_ctx *testid_ctx,
				uint32_t *module_id)
{
	ACVP_BUFFER_INIT(get_response_buf);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", acvp_id(*module_id)));

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, NULL, &get_response_buf,
			   acvp_http_get);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_certrequest_process(&get_response_buf, module_id));

out:
	acvp_free_buf(&get_response_buf);
	return ret;
}

static int amvp_certrequest_get_op(struct acvp_testid_ctx *testid_ctx,
				   const struct acvp_buf *response,
				   uint32_t *module_id)
{
	int ret;

	/* Analyze the result from the POST */
(void)response;
//	CKINT(amvp_certrequest_process(response, module_id));

//	if (!acvp_request_id(*module_id)) {
//		logger(LOGGER_DEBUG, LOGGER_C_ANY, "Cert request: %u\n",
//		       *module_id);
//		goto out;
//	}
    
	/* Remove */
	CKINT(sleep_interruptible(60, &acvp_op_interrupted));
	/* Implement the waiting */
#define AMVP_GET_DATAFILE_INFO_SLEEPTIME 30
	for (;;) {
		CKINT(amvp_certrequest_get(testid_ctx, module_id));

		/* Wait the requested amount of seconds */
		if (acvp_request_id(*module_id)) {
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

out:
	return ret;
}

/* POST /certRequests */
static int amvp_register_op(struct acvp_testid_ctx *testid_ctx,
			    struct json_object *request)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *result = NULL;
	uint32_t module_id;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				request,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_certrequest_process(&response_buf, &module_id));
	module_id = acvp_id(module_id);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained certRequest ID %u\n",
	       module_id);

	acvp_free_buf(&response_buf);

	CKINT(amvp_result_build(testid_ctx, module_id, &result));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", module_id));

	json_request = json_object_to_json_string_ext(
		result,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");
	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	/*
	 * Process the response and download the vectors. Except for the
	 * URL path names, the concept of how data is communicated is identical
	 * between ACVP and AMVP:
	 *
	 * ACVP testSessions == AMVP crSessions
	 * ACVP vectorSets == AMVP ievSets
	 *
	 * Thus, we can re-purpose the fetching functionality of the ACVP
	 * data for AMVP.
	 */
	//CKINT(acvp_process_req(testid_ctx, request, &response_buf));
	CKINT(amvp_certrequest_get_op(testid_ctx, &response_buf, &module_id));

out:
	testid_ctx->server_auth = NULL;
	acvp_free_buf(&response_buf);

	ACVP_JSON_PUT_NULL(result);

	return ret;
}

static int amvp_registration_build(struct acvp_testid_ctx *testid_ctx,
				   uint32_t module_id,
				   struct json_object **json_registration)
{
	struct json_object *registration, *entry, *array;
//	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	CKNULL(testid_ctx, -EINVAL);
	CKNULL(json_registration, -EINVAL);

	registration = json_object_new_array();
	CKNULL(registration, -ENOMEM);

	/* Array entry for version */
	CKINT(acvp_req_add_version(registration));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(registration, entry));

//	CKINT(acvp_create_urlpath(NIST_VAL_OP_MODULE, url, sizeof(url)));
//	CKINT(acvp_extend_string(url, sizeof(url), "/%u", module_id));
//	CKINT(json_object_object_add(entry, "moduleId",
//				     json_object_new_string(url)));
	CKINT(json_object_object_add(entry, "moduleId",
				     json_object_new_int((int)module_id)));

//	CKINT(acvp_create_urlpath(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	//TODO - real data
//	CKINT(acvp_extend_string(url, sizeof(url), "/%u", 1234));
	CKINT(json_object_object_add(entry, "vendorId",
				     json_object_new_int(1234)));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "contactId",  array));
	CKINT(json_object_array_add(array,
				    json_object_new_string("CVP-01234")));
	CKINT(json_object_array_add(array,
				    json_object_new_string("CVP-12345")));


	*json_registration = registration;

out:
	return ret;
}

/*
 * TOOD: use acvp_meta_register_get_id
 *
 * ISSUES:
 *	uses ID and not url
 * 	uses Initial instead of initial
 *	implements acvp_get_accesstoken as module registration returns new JWT
 */
static int amvp_module_process_id(const struct acvp_buf *response, uint32_t *id)
{
	struct json_object *resp = NULL, *data = NULL;
	uint32_t status_flag = 0, tmp_id;
	int ret;
	const char *status;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	/*
	 * {
	 *	"url": "/acvp/v1/requests/2",
	 *	"status": "approved",
	 *	"approvedUrl" : "/acvp/v1/vendors/2"
	 * }
	 */

	CKINT(json_get_string(data, "status", &status));
	if (!strncmp(status, "approved", 8)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates successful opoeration: %s\n",
		       status);
		CKINT(json_get_string(data, "approvedUrl", &status));
	} else if (!strncmp(status, "initial", 7)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates initial request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_INITIAL;
		CKINT(json_get_string(data, "url", &status));
	} else if (!strncmp(status, "processing", 10)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Request response indicates request processing: %s\n",
		       status);
		status_flag = ACVP_REQUEST_PROCESSING;
		CKINT(json_get_string(data, "url", &status));
	} else if (!strncmp(status, "rejected", 10)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates rejection of request: %s - Request information discarded locally to allow re-trying of publication.\n",
		       status);
		/*
		 * Set the ID to zero to allow performing a complete new
		 * publication operation. Yet, we throw an error to allow
		 * the user to know about the issue.
		 */
		ret = -EPERM;
		*id = 0;
		goto out;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Request response indicates unsuccessful operation: %s\n",
		       status);
		ret = -EOPNOTSUPP;
		goto out;
	}

	CKINT(acvp_get_trailing_number(status, &tmp_id));

	/* Reject a request ID */
	if (acvp_request_id(tmp_id)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Invalid request ID received from ACVP server (did the request IDs became so large that it interferes with the indicator bits?)\n");
		ret = -EFAULT;
		goto out;
	}

	tmp_id = acvp_id(tmp_id);
	tmp_id |= status_flag;

	*id = tmp_id;

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/* GET /modules/<id> */
static int amvp_module_get(struct acvp_testid_ctx *testid_ctx,
			   uint32_t *module_id)
{
	ACVP_BUFFER_INIT(response_buf);
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", *module_id));

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, NULL, &response_buf,
			   acvp_http_get);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_module_process(testid_ctx, &response_buf, module_id));

out:
	acvp_free_buf(&response_buf);

	return ret;
}

/* GET /requests/<id> */
static int amvp_module_get_id(struct acvp_testid_ctx *testid_ctx,
			      uint32_t *module_id)
{
	ACVP_BUFFER_INIT(response_buf);
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_REQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", acvp_id(*module_id)));

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, NULL, &response_buf,
			   acvp_http_get);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_module_process_id(&response_buf, module_id));

	if (!acvp_request_id(*module_id))
		CKINT(amvp_module_get(testid_ctx, module_id));

out:
	acvp_free_buf(&response_buf);

	return ret;
}

static int amvp_module_get_op(struct acvp_testid_ctx *testid_ctx,
			      const struct acvp_buf *response,
			      uint32_t *module_id)
{
	int ret;

	/* Analyze the result from the POST */
	CKINT(amvp_module_process_id(response, module_id));

	if (!acvp_request_id(*module_id)) {
		CKINT(amvp_module_get(testid_ctx, module_id));
		goto out;
	}

	/* Implement the waiting */
#define AMVP_GET_DATAFILE_INFO_SLEEPTIME 30
	for (;;) {
		CKINT(amvp_module_get_id(testid_ctx, module_id));

		/* Wait the requested amount of seconds */
		if (acvp_request_id(*module_id)) {
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

out:
	return ret;
}

/*
 * TOOD: should use acvp_module_register
 *
 * ISSUES:
 * 	calling of different processing callback
 * 	invocation of module build and register operation
 */
static int amvp_module_register_op(struct acvp_testid_ctx *testid_ctx,
				   struct json_object *request)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *registration = NULL;
	uint32_t module_id;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	/*
	 * The module registration JWT acts as the session JWT and thus must
	 * be maintained for the session.
	 */
	CKINT_LOG(acvp_init_auth(testid_ctx),
		  "Failure to initialize authtoken\n");

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				request,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));
   
	CKINT(amvp_module_get_op(testid_ctx, &response_buf, &module_id));
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Obtained module ID %u\n",
	       module_id);

	CKINT(amvp_registration_build(testid_ctx, module_id, &registration));

	/*
	 * Send the constructed message to the server and fetch the
	 * crSession data.
	 */
	CKINT(amvp_register_op(testid_ctx, registration));

out:
	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	acvp_free_buf(&response_buf);
	ACVP_JSON_PUT_NULL(registration);

	return ret;
}

#if 0

static int amvp_build_acvp_info(struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def;
	const struct acvp_net_proto *proto;
	const struct acvp_ctx *ctx;
	struct amvp_build_data *build_data;
	struct def_info *def_info;
	struct acvp_auth_ctx *auth;
	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	CKNULL(testid_ctx, -EINVAL);
	def = testid_ctx->def;
	CKNULL(def, -EINVAL);
	def_info = def->info;
	CKNULL(def_info, -EINVAL);

	ctx = testid_ctx->ctx;
	CKNULL(ctx, -EINVAL);
	build_data = ctx->private;
	CKNULL(build_data, -EINVAL);

	CKNULL(build_data->acvp_array, -EINVAL);
	CKNULL(build_data->module_array, -EINVAL);

	CKINT(acvp_convert_proto(amv_protocol, &proto));

	CKINT(acvp_init_auth(testid_ctx));
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Get certificate ID */
	auth = testid_ctx->server_auth;
	if (!auth->testsession_certificate_number) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No certificate number for test ID %u (%s) found\n",
		       testid_ctx->testid, def_info->module_name);
		ret = -EINVAL;
		goto out;
	}

	CKINT(acvp_create_urlpath_proto(proto, NIST_VAL_OP_ACVP,
					url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 auth->testsession_certificate_id));
	CKINT(json_object_array_add(build_data->acvp_array,
				    json_object_new_string(url)));

	CKINT(acvp_def_get_module_id(def_info));
	if (!def_info->acvp_module_id) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No module ID for test ID %u (%s) found\n",
		       testid_ctx->testid, def_info->module_name);
		return -EINVAL;
	}

	/* Entry for module ID */
	CKINT(acvp_create_urlpath_proto(proto,
					NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_module_id));
	CKINT(json_object_array_add(build_data->module_array,
				    json_object_new_string(url)));

out:
	acvp_release_auth(testid_ctx);
	return ret;
}

static int amvp_build_esvp_info(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_net_proto *proto;
	const struct acvp_ctx *ctx;
	struct amvp_build_data *build_data;
	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	ctx = testid_ctx->ctx;
	CKNULL(ctx, -EINVAL);
	build_data = ctx->private;
	CKNULL(build_data, -EINVAL);

	CKNULL(build_data->esvp_array, -EINVAL);

	CKINT(acvp_convert_proto(amv_protocol, &proto));

	CKINT(acvp_create_urlpath_proto(proto,
					NIST_VAL_OP_ESVP, url, sizeof(url)));
	//TODO - which number?
	CKINT(acvp_extend_string(url, sizeof(url), "/NUMBER_UNKOWN"));
	CKINT(json_object_array_add(build_data->esvp_array,
				    json_object_new_string(url)));

out:
	acvp_release_auth(testid_ctx);
	return ret;
}

static int amvp_alloc_testid(const struct acvp_ctx *ctx,
			     const struct definition *def,
			     uint32_t testid,
			     struct acvp_testid_ctx **testid_ctx_out)
{
	struct acvp_testid_ctx *testid_ctx;
	int ret;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);
	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));
	testid_ctx->sig_cancel_send_delete = true;

	*testid_ctx_out = testid_ctx;

out:
	return ret;
}

static int amvp_build_acvp(const struct acvp_ctx *ctx,
			   const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	CKINT(amvp_alloc_testid(ctx, def, testid, &testid_ctx));

	logger_status(LOGGER_C_ANY, "Gathering ACVP data for module %s\n",
		      def->info->module_name);
	CKINT(amvp_build_acvp_info(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

static int amvp_build_esvp(const struct acvp_ctx *ctx,
			   const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	CKINT(amvp_alloc_testid(ctx, def, testid, &testid_ctx));

	logger_status(LOGGER_C_ANY, "Gathering ESVP data for module %s\n",
		      def->info->module_name);
	CKINT(amvp_build_esvp_info(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

static int amvp_set_paths(struct acvp_ctx *ctx)
{
	const struct acvp_net_proto *proto;
	struct acvp_datastore_ctx *datastore = &ctx->datastore;
	int ret;

	/*
	 * TODO: currently we have no way of re-using the command-line
	 * provided path names!
	 */
	CKINT(acvp_get_proto(&proto));
	datastore->basedir = acvp_req_is_production() ?
			     (char *)proto->basedir_production :
			     (char *)proto->basedir;
	datastore->secure_basedir = acvp_req_is_production() ?
			     (char *)proto->secure_basedir_production :
			     (char *)proto->secure_basedir;

out:
	return ret;
}

DSO_PUBLIC
int amvp_register(struct acvp_ctx *ctx)
{
	struct acvp_opts_ctx *opts;
	struct acvp_testid_ctx testid_ctx;
	struct amvp_build_data build_data = { 0 };
	struct acvp_datastore_ctx *datastore = NULL;
	struct json_object *acvp_array = NULL, *esvp_array = NULL,
			   *module_array = NULL;
	char *tmp_base = NULL, *tmp_secure = NULL;
	struct json_object *amvp_registration = NULL, *array, *entry;
	bool threading_config;
	int ret;

	CKNULL(ctx, -EINVAL);
	opts = &ctx->options;

	threading_config = opts->threading_disabled;

	/*
	 * Threading must be disabled to avoid thrashing the filling of
	 * *acvp_array, *esvp_array, *module_array which use the service
	 * function that may perform threading.
	 */
	opts->threading_disabled = true;

	/*
	 * [
         *   {"algValidationId" : "/amv/v1/acvp/v2/123456"},
	 *   {"entropyId" : [{"/amv/v1/esv/v2/987654"}]},
         *   {"moduleId" : [{"/amv/v1/modules/0918273546"}]}
	 * ]
	 *
	 * The data is directly fetched from ACVP and ESVP data stores
	 */
	amvp_registration = json_object_new_array();
	CKNULL(amvp_registration, -ENOMEM);

	/* Array entry for version */
	CKINT(acvp_req_add_version(amvp_registration));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_array_add(amvp_registration, array));

	/* Array entry for request */
	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(array, entry));

	/* Array for ACVP ID */
	acvp_array = json_object_new_array();
	CKNULL(acvp_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "algValidationId", acvp_array));

	/* Array for Module ID */
	module_array = json_object_new_array();
	CKNULL(module_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "moduleId", module_array));

	build_data.acvp_array = acvp_array;
	build_data.module_array = module_array;
	ctx->private = &build_data;

	/*
	 * Now fill the ACVP/module array with the found data in the ACVP
	 * testvectors directory.
	 */
	datastore = &ctx->datastore;
	tmp_base = datastore->basedir;
	tmp_secure = datastore->secure_basedir;
	CKINT(acvp_set_proto(acv_protocol));
	CKINT(amvp_set_paths(ctx));
	CKINT(acvp_process_testids(ctx, &amvp_build_acvp));

	if (!json_object_array_length(acvp_array)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No ACVP data found! A module must have at least one approved crypto algo with one CAVP certificate!\n");
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (!json_object_array_length(module_array)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No module data found!\n");
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* Array for Entropy ID */
	esvp_array = json_object_new_array();
	CKNULL(esvp_array, -ENOMEM);

	build_data.esvp_array = esvp_array;

	/*
	 * Now fill the ESVP array with the found data in the ESVP
	 * testvectors directory.
	 */
	CKINT(acvp_set_proto(esv_protocol));
	CKINT(amvp_set_paths(ctx));
	CKINT(acvp_process_testids(ctx, &amvp_build_esvp));

	/* It is permissible to have no ESVP with the module. */
	if (json_object_array_length(esvp_array)) {
		CKINT(json_object_object_add(entry, "entropyId", esvp_array));
		esvp_array = NULL;
	}

	/* Switch back to AMVP definition */
	CKINT(acvp_set_proto(amv_protocol));
	datastore->basedir = tmp_base;
	datastore->secure_basedir = tmp_secure;

	CKINT(acvp_init_testid_ctx(&testid_ctx, ctx, NULL, 0));

	/* Now we can reenable threading as it was configured */
	opts->threading_disabled = threading_config;

	/*
	 * Send the constructed message to the server and fetch the
	 * crSession data.
	 */
	CKINT(amvp_register_op(&testid_ctx, amvp_registration));

out:
	if (datastore && tmp_base)
		datastore->basedir = tmp_base;
	if (datastore && tmp_secure)
		datastore->secure_basedir = tmp_secure;
	ACVP_JSON_PUT_NULL(amvp_registration);
	ACVP_JSON_PUT_NULL(esvp_array);
	return ret;
}

#else

static int amvp_module_build(struct acvp_testid_ctx *testid_ctx,
			     struct json_object **json_module)
{
	struct json_object *module_wrapper, *module, *module_info,
			   *seclevel_array;
	unsigned int i;
	int ret;

	CKNULL(testid_ctx, -EINVAL);
	CKNULL(json_module, -EINVAL);

	module_wrapper = json_object_new_array();
	CKNULL(module_wrapper, -ENOMEM);

	/* Array entry for version */
	CKINT(acvp_req_add_version(module_wrapper));

	module = json_object_new_object();
	CKNULL(module, -ENOMEM);
	CKINT(json_object_array_add(module_wrapper, module));

	CKINT(json_object_object_add(module, "schemaVersion",
				     json_object_new_string("Draft 1")));

	CKINT(json_object_object_add(module, "implementsOtar",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasNonApprovedMode",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "requiresInitialization",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasExcludedComponents",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasDegradedMode",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasPPAorPAI",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasEmbeddedOrBoundModule",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasCriticalFunctions",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasNonApprovedAlgorithmsInApprovedMode",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasExternalInputDevice",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasExternalOutputDevice",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesTrustedChannel",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "supportsConcurrentOperators",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesIdentityBasedAuthentication",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasMaintenanceRole",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "allowsOperatorToChangeRoles",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasDefaultAuthenticationData",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesEDC",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "allowsExternalLoadingOfSoftwareOrFirmware",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "containsNonReconfigurableMemory",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesOpenSource",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "providesMaintenanceAccessInterface",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasVentilationOrSlits",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasRemovableCover",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasTamperSeals",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasOperatorAppliedTamperSeals",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasEFPorEFT",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "outputsSensitiveDataAsPlaintext",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "supportsManualSSPEntry",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesSplitKnowledge",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasCVE",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasAdditionalMitigations",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "usesOtherCurve",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "supportsBypassCapability",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module, "hasOTPMemory",
				     json_object_new_boolean(0)));

	module_info = json_object_new_object();
	CKNULL(module_info, -ENOMEM);
	CKINT(json_object_object_add(module, "moduleInfo", module_info));

	//TODO populate with real info
	CKINT(json_object_object_add(module_info, "name",
				     json_object_new_string("name1")));
	CKINT(json_object_object_add(module_info, "count",
				     json_object_new_int(1)));
	CKINT(json_object_object_add(module_info, "description",
				     json_object_new_string("description1")));
	CKINT(json_object_object_add(module_info, "embodiment",
				     json_object_new_string("software")));
	CKINT(json_object_object_add(module_info, "type",
				     json_object_new_string("type1")));
	CKINT(json_object_object_add(module_info, "opEnvType",
				     json_object_new_string("opEnvType1")));
	CKINT(json_object_object_add(module_info, "submissionLevel",
				     json_object_new_string("submissionLevel1")));
	CKINT(json_object_object_add(module_info, "itar",
				     json_object_new_boolean(0)));
	CKINT(json_object_object_add(module_info, "overallSecurityLevel",
				     json_object_new_int(1)));

	seclevel_array = json_object_new_array();
	CKNULL(seclevel_array, -ENOMEM);
	CKINT(json_object_object_add(module, "secLevels", seclevel_array));

	for (i = 1; i <= 12; i++) {
		struct json_object *secentry;

		secentry = json_object_new_object();
		CKNULL(secentry, -ENOMEM);
		CKINT(json_object_array_add(seclevel_array, secentry));

		CKINT(json_object_object_add(secentry, "section",
					     json_object_new_int((int32_t)i)));

		CKINT(json_object_object_add(secentry, "level",
					     json_object_new_int(1)));
	}

	*json_module = module_wrapper;

out:
	return ret;
}

static int amvp_register_module(struct acvp_ctx *ctx)
{
	struct acvp_testid_ctx testid_ctx;
	struct json_object *module = NULL;
	int ret;

	CKNULL(ctx, -EINVAL);

	memset(&testid_ctx, 0, sizeof(testid_ctx));

	CKINT(amvp_module_build(&testid_ctx, &module));

	CKINT(acvp_init_testid_ctx(&testid_ctx, ctx, NULL, 0));

	/*
	 * Send the constructed message to the server and fetch the
	 * crSession data.
	 */
	CKINT(amvp_module_register_op(&testid_ctx, module));

out:
	ACVP_JSON_PUT_NULL(module);;
	return ret;
}

DSO_PUBLIC
int amvp_register(struct acvp_ctx *ctx)
{
	int ret;

	CKNULL(ctx, -EINVAL);

	CKINT(amvp_register_module(ctx));

out:
	return ret;
}

#endif
