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

static int amvp_certrequest_prereq_build(
	const struct acvp_testid_ctx *module_ctx, struct json_object *data)
{
	struct json_object *array;
	int ret;

	(void)module_ctx;

	// TODO get the ACVP / ESV from the database
	array = json_object_new_array();
	CKNULL(array, ENOMEM);
	CKINT(json_object_object_add(data, "algorithmCertificates", array));
	CKINT(json_object_array_add(array, json_object_new_string("A1")));

	array = json_object_new_array();
	CKNULL(array, ENOMEM);
	CKINT(json_object_object_add(data, "entropyCertificates", array));
	CKINT(json_object_array_add(array, json_object_new_string("E1")));

out:
	return ret;
}

/*
 * POST /amv/v1/certRequests/<id>/prerequisiteCertificates
 */
int amvp_certrequest_prereq(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	struct amvp_state *state = module_ctx->amvp_state;
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_EXT_BUFFER_INIT(request_buf);
	ACVP_BUFFER_INIT(response);
	struct json_object *request = NULL;
	int ret, ret2;
	const char *json_request;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url,
				  sizeof(url)),
				  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_PREREQ_CERTS));

	request = json_object_new_object();
	CKNULL(request, ENOMEM);
	CKINT(acvp_req_add_version(request));

	CKINT(amvp_certrequest_prereq_build(module_ctx, request))

	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
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

	/* Certificate prerequisites successfully submitted */
	state->cavp_certs_submitted = true;
	state->esv_certs_submitted = true;

	CKINT(_amvp_certrequest_status(certreq_ctx, &response,
				       amvp_certrequest_status_show_status));

out:
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response);
	return ret;
}
