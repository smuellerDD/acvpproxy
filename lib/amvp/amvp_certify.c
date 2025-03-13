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
#include "request_helper.h"
#include "term_colors.h"

/*
 * POST /amv/v1/certRequests/<id>/certify
 */
int amvp_certify(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct amvp_state *state = module_ctx->amvp_state;
	struct json_object *request = NULL;
	ACVP_BUFFER_INIT(response);
	int ret, ret2;

	CKINT(amvp_certrequest_status(certreq_ctx));

	/* Certify can only happen if  */
	if (state->overall_state < AMVP_REQUEST_STATE_COMPLETED) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Certification status does not allow finalization - information missing\n");
		ret = -EAGAIN;
		goto out;
	}

	if (state->overall_state < AMVP_REQUEST_STATE_APPROVED) {
		ACVP_EXT_BUFFER_INIT(request_buf);
		char url[ACVP_NET_URL_MAXLEN];
		const char *json_request;

		CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url,
			  sizeof(url)), "Creation of request URL failed\n");
		CKINT(acvp_extend_string(url, sizeof(url), "/%u",
					 certreq_ctx->vsid));
		CKINT(acvp_extend_string(url, sizeof(url), "/%s",
					 NIST_VAL_OP_CERTIFY));

		request = json_object_new_object();
		CKNULL(request, ENOMEM);
		CKINT(acvp_req_add_version(request));
		json_request = json_object_to_json_string_ext(
			request,
			JSON_C_TO_STRING_PLAIN |
			JSON_C_TO_STRING_NOSLASHESCAPE);
		CKNULL_LOG(json_request, -ENOMEM,
			   "JSON object conversion into string failed\n");

		request_buf.buf = (uint8_t *)json_request;
		request_buf.len = (uint32_t)strlen(json_request);

		ret2 = acvp_net_op(module_ctx, url, &request_buf, &response,
				   acvp_http_post);
		if (ret2 < 0) {
			ret = ret2;
			goto out;
		}

		CKINT(_amvp_certrequest_status(certreq_ctx, &response));

		/*
		 * After posting the certificate request, we have to get the
		 * updated status as it is not immediately reflected in the
		 * POST response.
		 */
		CKINT(amvp_certrequest_status(certreq_ctx));
	}

	if (state->overall_state >= AMVP_REQUEST_STATE_APPROVED) {
		logger_status(LOGGER_C_ANY,
			      "%sCertificate received for certification request ID %"PRIu64": %s%s\n",
			      TERM_COLOR_GREEN_INVERTED, certreq_ctx->vsid,
			      state->certificate, TERM_COLOR_NORMAL);
	} else {
		logger_status(LOGGER_C_ANY, "%sCertificate not yet received%s\n",
			      TERM_COLOR_YELLOW, TERM_COLOR_NORMAL);
	}

out:
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response);
	return ret;
}
