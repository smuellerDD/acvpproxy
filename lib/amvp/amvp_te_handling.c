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

#include "amvp_internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "term_colors.h"

/******************************************************************************
 * TE status processing
 ******************************************************************************/

static int amvp_te_status(const struct acvp_vsid_ctx *certreq_ctx,
			  struct json_object *data, const char *key,
			  const char *log, const char *status_file)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	ACVP_BUFFER_INIT(stat);
	struct json_object *sp;
	const char *str;
	size_t i;
	int ret;

	/* Get the expected evidence information */
	ret = json_find_key(data, key, &sp, json_type_array);
	if (ret) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}
	for (i = 0; i < json_object_array_length(sp); i++) {
		struct json_object *entry = json_object_array_get_idx(sp, i);

		CKINT(json_get_string(entry, "testRequirement", &str));

		logger_status(LOGGER_C_ANY,
			      "%s evidence for TE section %s not yet uploaded or received by NIST server\n",
			      log, str);
	}

	str = json_object_to_json_string_ext(
		sp, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat.buf = (uint8_t *)str;
	stat.len = (uint32_t)strlen(str);

	CKINT(acvp_store_file(module_ctx, &stat, 1, status_file));

out:
	return ret;
}

int amvp_ft_te_status(const struct acvp_vsid_ctx *certreq_ctx,
		      struct json_object *data)
{
	int ret;

	CKINT(amvp_te_status(certreq_ctx, data,
			     "expectedFunctionalTestEvidence",
			     "Functional Test",
			     "expected_functional_test_evidence.json"));

out:
	return ret;
}

int amvp_sc_te_status(const struct acvp_vsid_ctx *certreq_ctx,
		      struct json_object *data)
{
	int ret;

	CKINT(amvp_te_status(certreq_ctx, data,
			     "expectedSourceCodeEvidence",
			     "Source Code",
			     "expected_source_code_evidence.json"));

out:
	return ret;
}

/******************************************************************************
 * [FT|SC]-TE data uploading
 ******************************************************************************/

static int amvp_te_handle_response(const struct acvp_vsid_ctx *certreq_ctx,
				   const struct acvp_buf *response)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	int ret;

	CKINT(acvp_store_file(module_ctx, response, 1,
				datastore->testsession_certificate_info));

	logger_status(LOGGER_C_ANY,
		      "Available TE data uploaded to NIST server\n");

	CKINT(_amvp_certrequest_status(certreq_ctx, response));

out:
	return ret;
}

/*
 * POST /amv/v1/certRequests/<id>/evidence
 * POST /amv/v1/certRequests/<id>/sourcecode
 */
static int _amvp_te_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx,
				    const struct acvp_buf *buf,
				    const char *target)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *result = NULL;
	int ret, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s", target));

	register_buf.buf = buf->buf;
	register_buf.len = buf->len;
	ret2 = acvp_net_op(module_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(module_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_te_handle_response(certreq_ctx, &response_buf));

out:
	ACVP_JSON_PUT_NULL(result);
	acvp_free_buf(&response_buf);
	return ret;
}

int amvp_te_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx,
			    const struct acvp_buf *buf)
{
	struct json_object *resp = NULL, *data = NULL, *ptr;
	int ret;

	/* If we have no buffer, it means we should not do anything */
	CKNULL(buf, 0);

	CKINT(acvp_req_strip_version(buf, &resp, &data));

	if (json_find_key(data, "sourceCode", &ptr, json_type_object) == 0) {
		CKINT(_amvp_te_upload_evidence(certreq_ctx, buf,
					       NIST_VAL_OP_SOURCECODE));
	} else {
		CKINT(_amvp_te_upload_evidence(certreq_ctx, buf,
					       NIST_VAL_OP_EVIDENCE));
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/******************************************************************************
 * [FT|SC]-TE data gathering
 ******************************************************************************/

static int amvp_te_store(const struct acvp_vsid_ctx *certreq_ctx,
			 struct json_object *data)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	struct amvp_state *state = module_ctx->amvp_state;
	ACVP_BUFFER_INIT(te_buf);
	struct json_object *te;
	const char *json_request;
	int ret;

	CKNULL(certreq_ctx, -EINVAL);
	CKNULL(data, -EINVAL);

	/* Fetch the template only once */
	if (state->test_report_template_fetched)
		return 0;

	/* Get the expected evidence information */
	CKINT(json_find_key(data, "expectedEvidence", &te, json_type_array));

	json_request = json_object_to_json_string_ext(
		te, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	te_buf.buf = (uint8_t *)json_request;
	te_buf.len = (uint32_t)strlen(json_request);

	state->test_report_template_fetched = true;

	/* Store the vsID data in data store */
	CKINT(ds->acvp_datastore_write_vsid(
		certreq_ctx, datastore->amvp_testreportfile,
		false, &te_buf));

	logger_status(LOGGER_C_ANY,
		      "TE Template for certificate request %"PRIu64" obtained\n",
		      certreq_ctx->vsid);

out:
	return ret;
}

/*
 * GET /certRequests/<ID>/evidenceSets
 */
int amvp_te_get(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	struct amvp_state *state = module_ctx->amvp_state;
	struct json_object *resp = NULL, *data = NULL;
	ACVP_BUFFER_INIT(response_buf);
	ACVP_BUFFER_INIT(tmp);
	char url[ACVP_NET_URL_MAXLEN];
	const struct acvp_net_ctx *net;
	int ret, ret2;

	//TODO - reenable
	ret = 0;
	goto out;

	CKNULL(state, -EINVAL);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_EVIDENCESETS));

	ret2 = acvp_net_op(module_ctx, url, NULL, &response_buf, acvp_http_get);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_process_retry(certreq_ctx, &response_buf, url, NULL));

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(&response_buf, &resp, &data));

	/* Store the TE data */
	CKINT(amvp_te_store(certreq_ctx, data));

	CKINT(acvp_get_net(&net));
	tmp.buf = (uint8_t *)net->server_name;
	tmp.len = (uint32_t)strlen((char *)tmp.buf);
	CKINT(ds->acvp_datastore_write_vsid(certreq_ctx, datastore->srcserver,
					    true, &tmp));

	/* Get the status */
	CKINT(_amvp_certrequest_status(certreq_ctx, &response_buf));

	/* If the work is completed, ignore the rest */
	if (state->overall_state >= AMVP_REQUEST_STATE_COMPLETED)
		goto out;

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&response_buf);
	return ret;
}
