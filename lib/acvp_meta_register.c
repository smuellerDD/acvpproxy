/* ACVP operation for registering vendor, modules, persons, OE
 *
 * Copyright (C) 2019 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include "acvp_meta_internal.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"

/*
 * Process the response of GET /requests/<requestID> without the HTTP
 * operation
 */
static int acvp_meta_register_get_id(struct acvp_buf *response, uint32_t *id)
{
	struct json_object *resp = NULL, *data = NULL;
	uint32_t status_flag = 0, tmp_id;
	int ret;
	const char *uri, *status;

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
	} else if (!strncmp(status, "initial", 7)) {
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

	if (status_flag) {
		CKINT(json_get_string(data, "url", &uri));
	} else {
		CKINT(json_get_string(data, "approvedUrl", &uri));
	}

	/* Get the oe ID which is the last pathname component */
	CKINT(acvp_get_trailing_number(uri, &tmp_id));

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

	/*
	 * Indicate an error to the caller so that they have to re-obtain the
	 * ID
	 */
	if (status_flag) {
		logger_status(LOGGER_C_ANY,
			      "Request ID not obtained, request pending - please query the request again once NIST approved the request. The request ID that NIST needs to approve is %u\n",
			      acvp_id(tmp_id));
		ret = -EAGAIN;
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/* GET /requests/<id> */
int acvp_meta_obtain_request_result(const struct acvp_testid_ctx *testid_ctx,
				    uint32_t *id)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_BUFFER_INIT(response);
	uint32_t tmp_id = *id;
	int ret;
	char url[FILENAME_MAX];

	if (req_details->dump_register)
		return 0;

	/* The ID field does not contain a request ID */
	if (!acvp_request_id(tmp_id))
		return 0;

	/* Remove the mask indicator */
	tmp_id = acvp_id(tmp_id);

	logger_status(LOGGER_C_ANY, "Fetch request for ID %u\n", tmp_id);

	CKINT(acvp_create_url(NIST_VAL_OP_REQUESTS, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", tmp_id));

	CKINT(acvp_net_op(testid_ctx, url, NULL, &response, acvp_http_get));

	CKINT(acvp_meta_register_get_id(&response, id));

out:
	acvp_free_buf(&response);
	return ret;
}

int acvp_meta_register(const struct acvp_testid_ctx *testid_ctx,
		       struct json_object *json,
		       char *url, unsigned int urllen, uint32_t *id,
		       enum acvp_http_type submit_type)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_submission = NULL;
	ACVP_BUFFER_INIT(submit);
	ACVP_BUFFER_INIT(response);
	ACVP_BUFFER_INIT(tmpbuf);
	int ret;
	const char *json_request;

	CKNULL(id, -EINVAL);

	/* Provided ID is a request ID */
	if (acvp_request_id(*id)) {
		if (req_details->dump_register && json) {
			fprintf(stdout, "%s\n",
				json_object_to_json_string_ext(json,
						JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));

			return 0;
		}
		return acvp_meta_obtain_request_result(testid_ctx, id);
	}

	if (acvp_valid_id(*id))
		CKINT(acvp_extend_string(url, urllen, "/%u", *id));

	logger_status(LOGGER_C_ANY, "%s object\n",
	       (submit_type == acvp_http_delete) ? "Deleting" : "Registering");

	if (json) {
		logger_status(LOGGER_C_ANY, "%s\n",
			      json_object_to_json_string_ext(json,
				JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE));

		/* Build the JSON object to be submitted */
		json_submission = json_object_new_array();
		CKNULL(json_submission, -ENOMEM);

		/* Array entry for version */
		CKINT(acvp_req_add_version(json_submission));

		/* Add oe to submission JSON object */
		json_object_get(json);
		CKINT(json_object_array_add(json_submission, json));

		if (req_details->dump_register) {
			fprintf(stdout, "%s\n",
				json_object_to_json_string_ext(json_submission,
						JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
			ret = 0;
			goto out;
		}

		tmpbuf.buf = (uint8_t *)json_object_to_json_string_ext(
						json_submission,
						JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE);
		tmpbuf.len = (uint32_t)strlen((char *)tmpbuf.buf);
		CKINT(ds->acvp_datastore_write_testid(
						testid_ctx,
						"operational_environment.json",
						true, &tmpbuf));

		/* Convert the JSON buffer into a string */
		json_request = json_object_to_json_string_ext(json_submission,
						JSON_C_TO_STRING_PLAIN |
						JSON_C_TO_STRING_NOSLASHESCAPE);
		CKNULL_LOG(json_request, -ENOMEM,
			   "JSON object conversion into string failed\n");

		submit.buf = (uint8_t *)json_request;
		submit.len = (uint32_t)strlen(json_request);
	}

#if 0
	CKINT(ask_yes("Shall request to alter ACVP data base be sent to the ACVP Server?"));
#endif

	CKINT(acvp_net_op(testid_ctx, url, &submit, &response, submit_type));

	CKINT(acvp_meta_register_get_id(&response, id));

out:
	ACVP_JSON_PUT_NULL(json_submission);
	acvp_free_buf(&response);
	return ret;
}

int acvp_get_id_from_url(const char *url, uint32_t *id)
{
	uint32_t tmpid;
	int ret;

	/* We do not overwrite request IDs */
	if (acvp_request_id(*id)) {
		CKINT(acvp_get_trailing_number(url, &tmpid));

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Received ID %u from ACVP server, but have a request ID %u on file - not changing the request ID\n",
		       tmpid, acvp_id(*id));
	} else {
		CKINT(acvp_get_trailing_number(url, id));
	}

out:
	return ret;
}

int acvp_search_to_http_type(int search_errno, unsigned int type,
			     const struct acvp_opts_ctx *ctx_opts, uint32_t id,
			     enum acvp_http_type *http_type)
{
	if (ctx_opts->show_db_entries) {
		*http_type = acvp_http_none;
		return 0;
	}

	/* Only the errno of ENOENT is converted to HTTP request type */
	if (search_errno && search_errno != -ENOENT)
		return search_errno;

	/* If we did not find a match, update the module definition */
	if (search_errno == -ENOENT) {
		if (ctx_opts->update_db_entry & type) {
			*http_type = acvp_http_put;
		} else if (ctx_opts->delete_db_entry &
			   (type | ACVP_OPTS_DELUP_FORCE)) {
			*http_type = acvp_http_delete;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Definition for ID %u different than found on ACVP server - you need to perform a (re)register operation\n",
			       id);
			return -ENOENT;
		}

		return 0;

	/*
	 * We only attempt a delete if we have a match between the ACVP server
	 * DB and our configurations. We do not want to delete unknown
	 * definitions. Yet, if we are forced to perform the delete, we will
	 * do that.
	 */
	} else if (ctx_opts->delete_db_entry & ACVP_OPTS_DELUP_MODULE) {
		*http_type = acvp_http_delete;
		return 0;
	}

	*http_type = acvp_http_none;

	return 0;
}
