/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#include "amvpproxy.h"
#include "aux_helper.h"
#include "internal.h"
#include "request_helper.h"

static int amvp_req_build(const struct acvp_testid_ctx *testid_ctx,
			  struct json_object *request)
{
	(void)testid_ctx;
	(void)request;

	return -EOPNOTSUPP;
}

static int amvp_process_req(struct acvp_testid_ctx *testid_ctx,
			    struct json_object *request,
			    struct acvp_buf *response)
{
	(void)testid_ctx;
	(void)request;
	(void)response;

	return -EOPNOTSUPP;
}

/* POST /testSessions */
static int amvp_register_op(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	const struct definition *def = testid_ctx->def;
	const struct def_info *info = def->info;
	struct json_object *request = NULL;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKINT_LOG(acvp_init_auth(testid_ctx),
		  "Failure to initialize authtoken\n");

	request = json_object_new_array();
	CKNULL(request, -ENOMEM);

	/* Construct the registration message. */
	CKINT_LOG(amvp_req_build(testid_ctx, request),
		  "Failure to create registration message\n");

	if (!req_details->dump_register)
		sig_enqueue_ctx(testid_ctx);

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

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_REG, url, sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);
	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	/* Process the response and download the vectors. */
	CKINT(amvp_process_req(testid_ctx, request, &response_buf));

out:
	if (!req_details->dump_register)
		sig_dequeue_ctx(testid_ctx);

	if (ret && testid_ctx)
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failure to request testID %u - module %s (%s)\n",
		       testid_ctx->testid, info->module_name, info->impl_name);

	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response_buf);

	return ret;
}

static int _amvp_register(const struct acvp_ctx *ctx,
			  const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx;
	int ret;

	(void)testid;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);
	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, 0));
	testid_ctx->sig_cancel_send_delete = true;

	logger_status(LOGGER_C_ANY, "Register module %s\n",
		      def->info->module_name);
	CKINT(amvp_register_op(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int amvp_register(const struct acvp_ctx *ctx)
{
	return acvp_register_cb(ctx, &_amvp_register);
}

static int _amvp_continue(const struct acvp_ctx *ctx,
			  const struct definition *def,
			  const uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);

	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));

	ret = -EOPNOTSUPP;

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int amvp_continue(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx));

	CKINT(acvp_process_testids(ctx, &_amvp_continue));

out:
	return ret;
}
