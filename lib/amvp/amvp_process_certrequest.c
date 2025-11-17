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

enum amvp_certrequest_te_status {
	amvp_certrequest_te_status_unknown,
	amvp_certrequest_te_status_submitted,	// TE evidence for type submitted
	amvp_certrequest_te_status_pending,	// TE evidence for type not submitted
	amvp_certrequest_te_status_not_requested // Type unrelated to TE
};

/*
 * Analyze something like this
 * [
      {
        "types":[
          "SC-TE",
          "FT-TE"
        ],
        "submitted":[
          "FT-TE"
        ]
      }
    ],
 */
static int amvp_certrequest_open_te_one(struct json_object *answer,
					const char *te_type, size_t te_type_len,
					enum amvp_certrequest_te_status	*status)
{
	const char *str;
	size_t i;
	int ret;

	*status = amvp_certrequest_te_status_unknown;

	/* If we have NULL, do not bother */
	CKNULL(answer, -ENOENT);

	if (!json_object_is_type(answer, json_type_array))
		return -EINVAL;

	/* Empty array - no entries */
	if (json_object_array_length(answer) == 0)
		return -ENOENT;

	for (i = 0; i < json_object_array_length(answer); i++) {
		size_t j;
		struct json_object *data, *array_member;
		bool te_type_found = false;

		array_member = json_object_array_get_idx(answer, i);
		CKNULL(array_member, -EINVAL);

		CKINT(json_find_key(array_member, "types", &data,
				    json_type_array));
		for (j = 0; j < json_object_array_length(data); j++) {
			struct json_object *entry =
				json_object_array_get_idx(data, j);

			str = json_object_get_string(entry);

			if (strlen(str) == te_type_len &&
			    !memcmp(te_type, str, te_type_len)) {
				te_type_found = true;
				break;
			}

		}

		if (!te_type_found) {
			*status = amvp_certrequest_te_status_not_requested;
			continue;
		}

		CKINT(json_find_key(array_member, "submitted", &data,
				    json_type_array));
		for (j = 0; j < json_object_array_length(data); j++) {
			struct json_object *entry =
				json_object_array_get_idx(data, j);

			str = json_object_get_string(entry);

			if (!memcmp(te_type, str, te_type_len)) {
				*status = amvp_certrequest_te_status_submitted;
				goto out;
			}

		}

		*status = amvp_certrequest_te_status_pending;
		break;
	}

out:
	return ret;
}

static void amvp_certrequest_open_one(enum amvp_certrequest_te_status status,
				      const char *str, const char *te_type,
				      bool *header_printed)
{
	switch (status) {
	case amvp_certrequest_te_status_pending:
		if (!*header_printed) {
			*header_printed = true;
			logger_status(LOGGER_C_ANY,
				      "%sThe following TEs for type %s are pending:%s\n",
				      TERM_COLOR_YELLOW, te_type,
				      TERM_COLOR_NORMAL);

		}
		printf("\t%s%s - TE type %s required and pending%s\n",
			TERM_COLOR_YELLOW, str, te_type,
			TERM_COLOR_NORMAL);
		break;
	case amvp_certrequest_te_status_submitted:
		if (!*header_printed) {
			*header_printed = true;
			logger_status(LOGGER_C_ANY,
				      "%sThe following TEs for type %s are pending:%s\n",
				      TERM_COLOR_YELLOW, te_type,
				      TERM_COLOR_NORMAL);

		}
		printf("\t%s%s - TE type %s required and submitted%s\n",
			TERM_COLOR_GREEN, str, te_type,
			TERM_COLOR_NORMAL);
		break;
	case amvp_certrequest_te_status_not_requested:
	case amvp_certrequest_te_status_unknown:
	default:
		break;
	}
}

static int amvp_certrequest_open_te(const struct json_object *data,
				    const char *key, const char *te_type,
				    size_t te_type_len,
				    enum amvp_certrequest_status_show show)
{
	struct json_object *array, *answer;
	size_t i;
	const char *str;
	enum amvp_certrequest_te_status status;
	int ret;
	bool completed = false, header_printed = false;

	if (show != amvp_certrequest_status_show_all)
		return 0;

	ret = json_find_key(data, key, &array, json_type_array);

	/* If data is not present, do not bother */
	if (ret == -ENOENT)
		return 0;

	CKINT(ret);

	if (json_object_array_length(array) == 0)
		return 0;

	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *te = json_object_array_get_idx(array, i);

		CKINT(json_get_string(te, "te", &str));

		CKINT(json_get_bool(te, "complete", &completed));

		if (completed)
			continue;

		CKINT(json_find_key(te, "required", &answer, json_type_array));

		ret = amvp_certrequest_open_te_one(answer, te_type, te_type_len,
						   &status);

		/*
		 * TE type found: since we are in required, out type must be
		 * there
		 */
		if (ret == 0) {
			amvp_certrequest_open_one(status, str, te_type,
						  &header_printed);
			switch (status) {
			case amvp_certrequest_te_status_pending:
			case amvp_certrequest_te_status_submitted:
				continue;
			case amvp_certrequest_te_status_not_requested:
			case amvp_certrequest_te_status_unknown:
			default:
				break;
			}
		} else if (ret != -ENOENT) {
			goto out;
		}
		/* else if (ret == -ENOENT) => go to next line */

		CKINT(json_find_key(te, "oneOf", &answer, json_type_array));

		ret = amvp_certrequest_open_te_one(answer, te_type, te_type_len,
						   &status);
		if (ret == 0) {
			amvp_certrequest_open_one(status, str, te_type,
						  &header_printed);
		} else if (ret != -ENOENT) {
			goto out;
		}
		/* else if (ret == -ENOENT) => go to round */
	}

	ret = 0;

out:
	return ret;
}

static int amvp_certrequest_open_sp(const struct json_object *data)
{
	struct json_object *array;
	size_t i;
	int ret, sp_section;

	ret = json_find_key(data, "missingSecurityPolicySection", &array,
			    json_type_array);

	/* If data is not present, do not bother */
	if (ret == -ENOENT)
		return 0;

	CKINT(ret);

	if (json_object_array_length(array) == 0)
		return 0;

	logger_status(LOGGER_C_ANY,
		      "%sThe following SP sections are pending:%s\n",
		      TERM_COLOR_YELLOW, TERM_COLOR_NORMAL);
	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *sp = json_object_array_get_idx(array, i);

		if (!json_object_is_type(sp, json_type_int)) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Unknown object in SP array\n");
			continue;
		}

		sp_section = json_object_get_int(sp);

		printf("\t%d\n", sp_section);
	}

out:
	return ret;
}


static int amvp_certrequest_open_certs(const struct json_object *data,
				       const char *key)
{
	struct json_object *array;
	size_t i;
	const char *str;
	int ret;

	ret = json_find_key(data, key, &array, json_type_array);

	/* If data is not present, do not bother */
	if (ret == -ENOENT) {
		logger_status(LOGGER_C_ANY,
		      "%sNo %s are uploaded:%s\n",
		      TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		return 0;
	}

	CKINT(ret);

	if (json_object_array_length(array) == 0)
		return 0;

	logger_status(LOGGER_C_ANY,
		      "%sThe following %s are uploaded:%s\n",
		      TERM_COLOR_GREEN, key, TERM_COLOR_NORMAL);
	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *cert = json_object_array_get_idx(array, i);

		if (!json_object_is_type(cert, json_type_string)) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Unknown object in %s array\n", key);
			continue;
		}

		str = json_object_get_string(cert);

		printf("\t%s\n", str);
	}

out:
	return ret;
}

#define logger_status_check(show, class, fmt...)                               \
	if (show != amvp_certrequest_status_show_none)                         \
		logger(LOGGER_STATUS, class, ##fmt)

static int amvp_certrequest_status_check(
	const struct acvp_vsid_ctx *certreq_ctx, const struct json_object *data,
	unsigned int *status, const char *key,
	enum amvp_certrequest_status_show show)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct amvp_state *state = module_ctx->amvp_state;
	const char *str;
	int ret;

	*status = 0;

	/* Get the status */
	CKINT(json_get_string(data, key, &str));
	if (!strncasecmp(str, "initial", 7)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sProcessing (%s) initial - not all evidence submitted%s\n",
				    TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_INITIAL;
	} else if (!strncasecmp(str, "ready", 5) ||
		   !strncasecmp(str, "acceptingSubmissions", 20)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sProcessing (%s) ongoing - not all evidence submitted%s\n",
				    TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_ONGOING;
	} else if (!strncasecmp(str, "requirementsSubmitted", 21)) {
		if (!state->cavp_certs_submitted ||
		    !state->esv_certs_submitted) {
			logger_status_check(show, LOGGER_C_ANY,
				"%sOverall processing (%s) completed but submit ESV/CAVP certificates with --certprereq%s\n",
				TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		} else {
			logger_status_check(show, LOGGER_C_ANY,
				"%sOverall processing (%s) completed: request certificate with --certify%s\n",
				TERM_COLOR_GREEN_INVERTED, key,
				TERM_COLOR_NORMAL);
		}
		*status = AMVP_REQUEST_STATE_COMPLETED_OVERALL;
	} else if (!strncasecmp(str, "submitted", 9)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sProcessing (%s) completed%s\n",
				    TERM_COLOR_GREEN, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_COMPLETED;
	} else if (!strncasecmp(str, "pendingGeneration", 17)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sPending generation (%s): fetch SP with --fetch-sp%s\n",
				    TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_PENDING_GENERATION;
	} else if (!strncasecmp(str, "processingSubmission", 20)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sAMVP server processes request (%s)%s\n",
				    TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_PENDING_PROCESSING_SUBMISSION;
	} else if (!strncasecmp(str, "processingGeneration", 20)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sAMVP server processes SP generation request (%s)%s\n",
				    TERM_COLOR_YELLOW, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_PENDING_PROCESSING_GENERATION;
	} else if (!strncasecmp(str, "inReview", 8)) {
		logger_status_check(show, LOGGER_C_ANY,
				    "%sAMVP server request in review (%s)%s\n",
				    TERM_COLOR_GREEN, key, TERM_COLOR_NORMAL);
		*status = AMVP_REQUEST_STATE_IN_REVIEW;
	} else if (!strncasecmp(str, "approved", 8)) {
		const char *str2;

		CKINT(json_get_string(data, "validationCertificate", &str2));
		logger_status_check(show, LOGGER_C_ANY,
				    "%sAMVP Processing completed - certificate %s awarded%s\n",
				    TERM_COLOR_GREEN_INVERTED, str2,
				    TERM_COLOR_NORMAL);

		*status = AMVP_REQUEST_STATE_APPROVED;
	} else if (!strncasecmp(str, "rejected", 8)) {
		struct json_object *rule;

		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "AMVP server rejected request request (%s) - you have to start from scratch\n",
		       key);

		if (json_object_object_get_ex(data, "ruleFeedback", &rule)) {
			json_logger(LOGGER_ERR, LOGGER_C_ANY, rule,
				    "AMVP Processing rejected due to the following reasons");
		}

		*status = AMVP_REQUEST_STATE_REJECTED;
		ret = -EBADMSG;
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
			     const struct acvp_buf *response,
			     enum amvp_certrequest_status_show show)
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
	CKINT(amvp_certrequest_status_check(certreq_ctx, data,
					    &state->overall_state, "status",
					    show));

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
	ret = amvp_certrequest_status_check(certreq_ctx, data, &state->sp_state,
					    "securityPolicyStatus", show);
	if (ret == -ENOENT) {
		CKINT(amvp_sp_status(certreq_ctx, data));
	} else if (ret) {
		goto out;
	}

	CKINT(amvp_certrequest_open_sp(data));

	/*
	 * TE status
	 *
	 * First check for the status which is only present if all is submitted.
	 * If it is not present, check for the individual FT TE sections.
	 */
	CKINT(amvp_certrequest_status_check(certreq_ctx, data,
					    &state->ft_te_state,
					    "evidenceStatus", show));

	if (state->ft_te_state <= AMVP_REQUEST_STATE_ONGOING) {
		CKINT(amvp_ft_te_status(certreq_ctx, data));
		CKINT(amvp_certrequest_open_te(data, "evidenceList", "FT-TE",
					       5, show));
		CKINT(amvp_certrequest_open_te(data, "evidenceList", "SC-TE",
					       5, show));
		CKINT(amvp_certrequest_open_te(data, "evidenceList", "OD-TE",
					       5, show));
		CKINT(amvp_certrequest_open_te(data, "evidenceList",
					       "OD(FSM)-TE", 10, show));
	}

	CKINT(amvp_certrequest_open_certs(data, "entropyCertificates"));
	CKINT(amvp_certrequest_open_certs(data, "algorithmCertificates"));

out:
	if (!ret)
		ret = amvp_write_status(module_ctx);

	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/*
 * GET /certRequests/<id>
 */
int amvp_certrequest_status(const struct acvp_vsid_ctx *certreq_ctx,
			    enum amvp_certrequest_status_show show)
{
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_BUFFER_INIT(response);
	int ret;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
				  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_process_retry(certreq_ctx, &response, url,
				 acvp_store_vector_debug));

	/* Analyze the result */
	CKINT(_amvp_certrequest_status(certreq_ctx, &response, show));

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

	/*
	 * Initialize the certRequestID directory for later potential re-load.
	 */
	CKINT(acvp_store_vector_status(&certreq_ctx,
	      "certRequest downloading commences\n"));

	/*
	 * Get the TE Template data.
	 */
	CKINT(amvp_te_get(&certreq_ctx));

	/*
	 * Get the status
	 */
	CKINT(amvp_certrequest_status(&certreq_ctx,
				      amvp_certrequest_status_show_all));

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

	/*
	 * For the time being, we use the certificate request ID for both, the
	 * module ID and the vsID
	 */
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
	struct json_object *registration = NULL;
	struct json_object_iter reg_data;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	def = module_ctx->def;
	CKNULL(def, -EINVAL);
	amvp = def->amvp;
	CKNULL(amvp, -EINVAL);

	/*
	 * Merge all data to be registered
	 */
	registration = json_object_new_object();
	CKNULL(registration, ENOMEM);
	CKINT(acvp_req_add_version(registration));
	CKINT(acvp_req_add_version(registration));
	json_object_object_foreachC(amvp->registration_definition, reg_data) {
		CKINT(json_object_object_add(registration, reg_data.key,
					     reg_data.val));
		json_object_get(reg_data.val);
	}
	CKINT(json_object_object_add(registration, "module",
				     amvp->validation_definition));
	json_object_get(amvp->validation_definition);

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				registration,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		registration,
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

	/* First: process the module data */
	CKINT(amvp_module_process_req(module_ctx, &response_buf));

	/* Second: process the certrequest data */
	CKINT(amvp_certrequest_process_req(module_ctx, &response_buf));

out:
	module_ctx->server_auth = NULL;
	acvp_free_buf(&response_buf);

	ACVP_JSON_PUT_NULL(registration);

	return ret;
}

/*
 * Register a certificate request for a given module
 */
int amvp_certrequest_register(struct acvp_testid_ctx *module_ctx)
{
	int ret;

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
