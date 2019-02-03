/* ACVP proxy protocol handler for publishing test results
 *
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "threading_support.h"

/* GET /testSessions/<testSessionId> */
static int acvp_get_testid_metadata(const struct acvp_testid_ctx *testid_ctx,
				    struct acvp_buf *response_buf)
{
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_testid_url(testid_ctx, url, sizeof(url)));

	ret2 = acvp_process_retry_testid(testid_ctx, response_buf, url);

	if (!response_buf->buf || !response_buf->len) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ACVP server did not provide meta data for testSession ID %u\n",
		       testid_ctx->testid);
		ret = -EINVAL;
		goto out;
	}

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response_buf->buf);

	if (ret2) {
		ret = ret2;
		goto out;
	}

out:
	return ret;
}

/* PUT /testSessions/<testSessionId> */
static int acvp_publish_request(const struct acvp_testid_ctx *testid_ctx,
				struct json_object *publish)
{
	const struct acvp_net_ctx *net;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_na_ex netinfo;
	ACVP_BUFFER_INIT(request_buf);
	ACVP_BUFFER_INIT(response_buf);
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	/* Log into the ACVP server using the TOTP authentication */
	CKINT(acvp_login(testid_ctx));

	CKINT(acvp_testid_url(testid_ctx, url, sizeof(url)));

	request_buf.buf = (uint8_t *)json_object_to_json_string_ext(publish,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	request_buf.len = strlen((char *)request_buf.buf);

	CKINT(acvp_get_net(&net));
	netinfo.net = net;
	netinfo.url = url;
	netinfo.server_auth = auth;
	mutex_reader_lock(&auth->mutex);
	ret = na->acvp_http_put(&netinfo, &request_buf, &response_buf);
	mutex_reader_unlock(&auth->mutex);

	if (response_buf.buf && response_buf.len) {
		logger(ret ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
		       "Received following server response: %s\n",
		       response_buf.buf);
	}

out:
	acvp_free_buf(&response_buf);
	return ret;
}

static int acvp_publish_ready(const struct acvp_testid_ctx *testid_ctx)
{
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(response);
	int ret;
	bool val;

	CKINT(acvp_get_testid_metadata(testid_ctx, &response));

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(response.buf, &req, &entry));

	/* Check that all test vectors passed */
	CKINT(json_get_bool(entry, "passed", &val));
	if (!val) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP server reports that not all vectors for testID %u passed - rejecting to publish\n",
		       testid_ctx->testid);
		ret = -EBADMSG;
		goto out;
	}

	/* Check that vector is publishable */
	CKINT(json_get_bool(entry, "publishable", &val));
	if (!val) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP server reports that testID %u is not publishable - rejecting to publish\n",
		       testid_ctx->testid);
		ret = -EBADMSG;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);
	return ret;
}

static int acvp_publish_build(const struct acvp_testid_ctx *testid_ctx,
			      struct json_object **json_publish)
{
	const struct definition *def = testid_ctx->def;
	const struct def_info *def_info = def->info;
	const struct def_oe *def_oe = def->oe;
	struct json_object *pub = NULL;
	int ret = -EINVAL;
	char url[ACVP_NET_URL_MAXLEN];

	if (!def_info->acvp_module_id || !def_oe->acvp_oe_id) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No module or OE ID found\n");
		return -EINVAL;
	}

	/*
	 * {
	 *	"moduleUrl": "/acvp/v1/modules/20",
	 *	"oeUrl": "/acvp/v1/oes/60",
	 *	"algorithmPrerequisites": [{
	 *		"algorithm": "AES-GCM",
	 *		"prerequisites": [
	 *			{
	 *				"algorithm": "AES",
	 *				"validationId": "123456"
	 *			},
	 *			{
	 *				"algorithm": "DRBG",
	 *				"validationId": "123456"
	 *			}
	 *		]
	 *	}],
	 *	"signature": {
	 *		"algorithm": "SHA256RSA",
	 *		"certificate": "{base64encodedcertificate}",
	 *		"digitalSignature": "{base64encodedsignature}"
	 *	}
	 * }
	 */

	/*
	 * The prerequisites are optional if they are always included into
	 * the original requests. This is the case with our ACVP Proxy.
	 * Thus, we do not add those.
	 */

	pub = json_object_new_object();
	CKNULL(pub, -ENOMEM);

	CKINT(acvp_create_urlpath(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_module_id));
	CKINT(json_object_object_add(pub, "moduleUrl",
				     json_object_new_string(url)));

	CKINT(acvp_create_urlpath(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_oe->acvp_oe_id));
	CKINT(json_object_object_add(pub, "oeUrl",
				     json_object_new_string(url)));

	//TODO what signature is to be added?

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, pub, "Vendor JSON object");

	*json_publish = pub;

	return 0;

out:
	ACVP_JSON_PUT_NULL(pub);
	return ret;
}

static int acvp_publish_testid(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_publish = NULL;
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	logger_status(LOGGER_C_ANY, "Publishing testID %u\n",
		      testid_ctx->testid);

	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Verify / register the vendor information */
	CKINT(acvp_vendor_handle(testid_ctx));

	/* Verify / register the operational environment information */
	CKINT(acvp_oe_handle(testid_ctx));

	/* Verify / register the operational environment information */
	CKINT(acvp_module_handle(testid_ctx));

	/* No actual work if we just dumping the data */
	if (req_details->dump_register)
		goto out;

	/* Will the ACVP server accept our publication request? */
	CKINT(acvp_publish_ready(testid_ctx));

	/* Create publication JSON data */
	CKINT(acvp_publish_build(testid_ctx, &json_publish));

	/* Do it: send the publication request to the ACVP server */
	CKINT(acvp_publish_request(testid_ctx, json_publish));

out:
	acvp_release_auth(testid_ctx);
	ACVP_JSON_PUT_NULL(json_publish);
	return ret;
}

static int _acvp_publish(const struct acvp_ctx *ctx,
			 const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->testid = testid;

	if (clock_gettime(CLOCK_REALTIME, &testid_ctx->start)) {
		ret = -errno;
		goto out;
	}

	CKINT(acvp_publish_testid(testid_ctx));

out:
	acvp_release_testid(testid_ctx);

	return ret;
}

DSO_PUBLIC
int acvp_publish(const struct acvp_ctx *ctx)
{
	return acvp_process_testids(ctx, &_acvp_publish);
}
