/* Handle the ACVP purchase requests
 *
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "acvp_error_handler.h"
#include "acvpproxy.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"

/* GET /purchase/options */
DSO_PUBLIC
int acvp_purchase_get_options(const struct acvp_ctx *ctx)
{
	struct json_object *req = NULL, *entry, *array;
	struct acvp_testid_ctx testid_ctx;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	size_t i;
	int ret;

	memset(&testid_ctx, 0, sizeof(testid_ctx));

	CKINT(acvp_create_url(NIST_VAL_OP_PURCHASE_OPTIONS, url, sizeof(url)));

	testid_ctx.ctx = ctx;
	CKINT(acvp_init_auth(&testid_ctx));

	CKINT(acvp_net_op(&testid_ctx, url, NULL, &response, acvp_http_get));

	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_find_key(entry, "data", &array, json_type_array));

	fprintf(stdout, "%-8s | %-15s | %-32s | %-14s\n", "Purchase", "Name",
		"Description", "Price");
	fprintf(stdout, "%-8s | %-15s | %-32s | %-14s\n", "Option", " ", " ",
		" ");
	fprintf(stdout, "%-8s-+-%-15s-+-%-32s-+-%-14s\n", "--------",
		"---------------", "--------------------------------",
		"--------------");

	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *purchase_option;
		const char *name, *description, *price, *opt_url;
		uint64_t opt;

		purchase_option = json_object_array_get_idx(array, i);

		if (!purchase_option)
			break;

		CKINT(json_get_string(purchase_option, "url", &opt_url));
		CKINT(acvp_get_trailing_number(opt_url, &opt));
		CKINT(json_get_string(purchase_option, "name", &name));
		CKINT(json_get_string(purchase_option, "description",
				      &description));
		CKINT(json_get_string(purchase_option, "price", &price));
		fprintf(stdout, "%-8"PRIu64" | %-15s | %-32s | %-14s\n", opt, name,
			description, price);
	}

out:
	acvp_release_auth(&testid_ctx);
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);
	return ret;
}

/* GET /lab/availablevectorsets */
DSO_PUBLIC
int acvp_purchase_list_available_vsids(const struct acvp_ctx *ctx)
{
	struct json_object *req = NULL, *entry;
	struct acvp_testid_ctx testid_ctx;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	const char *available;
	int ret;

	memset(&testid_ctx, 0, sizeof(testid_ctx));

	CKINT(acvp_create_url(NIST_VAL_OP_AVAIL_VSIDS, url, sizeof(url)));

	testid_ctx.ctx = ctx;
	CKINT(acvp_init_auth(&testid_ctx));

	CKINT(acvp_net_op(&testid_ctx, url, NULL, &response, acvp_http_get));

	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_get_string(entry, "available", &available));
	fprintf(stdout,
		"Number of vector sets that available for testing: %s\n",
		available);

out:
	acvp_release_auth(&testid_ctx);
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);
	return ret;
}

/* POST /purchase */
DSO_PUBLIC
int acvp_purchase(const struct acvp_ctx *ctx, uint32_t opt, uint32_t qty,
		  const char *ponumber)
{
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *request = NULL, *array, *entry, *resp = NULL;
	struct acvp_testid_ctx testid_ctx;
	ACVP_BUFFER_INIT(response);
	struct acvp_ext_buf purchase_buf;
	const char *json_request, *status;
	char url[ACVP_NET_URL_MAXLEN];
	enum acvp_error_code code = ACVP_ERR_NO_ERR;
	int ret, ret2;

	memset(&testid_ctx, 0, sizeof(testid_ctx));

	/* Prepare the purchase JSON structure */
	CKINT(acvp_create_urlpath(NIST_VAL_OP_PURCHASE_OPTIONS, url,
				  sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", opt));

	request = json_object_new_array();
	CKNULL(request, -ENOMEM);

	/* Array entry for version */
	CKINT(acvp_req_add_version(request));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(request, entry));

	if (ponumber) {
		CKINT(json_object_object_add(entry, "purchaseOrderNumber",
					     json_object_new_string(ponumber)));
	}

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "items", array));

	/* Array entry for request */
	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(array, entry));

	CKINT(json_object_object_add(entry, "purchaseOptionUrl",
				     json_object_new_string(url)));
	CKINT(json_object_object_add(entry, "quantity",
				     json_object_new_int((int32_t)qty)));

	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				request,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	if (ask_yes("Do you really want to perform a purchase")) {
		ret = -ENOENT;
		goto out;
	}

	/* Post the purchase request to the server */
	CKINT(acvp_create_url(NIST_VAL_OP_PURCHASE, url, sizeof(url)));
	testid_ctx.ctx = ctx;
	CKINT_LOG(acvp_init_auth(&testid_ctx),
		  "Failure to initialize authtoken\n");

	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	purchase_buf.buf = (uint8_t *)json_request;
	purchase_buf.len = (uint32_t)strlen(json_request);

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "About to post\n%s\n",
	       purchase_buf.buf);

	/* Send the capabilities to the ACVP server. */
	ret2 = acvp_net_op(&testid_ctx, url, &purchase_buf, &response,
			   acvp_http_post);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_file(&testid_ctx, &response, ret2,
			      "purchase_response.json"));

	CKINT(acvp_error_convert(&response, ret2, &code));

	if (code != ACVP_ERR_NO_ERR) {
		ret = (int)code;
		goto out;
	}

	/* Analyze the ACVP server answer */
	CKINT(acvp_req_strip_version(&response, &resp, &entry));
	CKINT(json_get_string(entry, "message", &status));

	/*
	 * The "status" variable may contain:
	 *
	 * * "unlimited" for unlimited number of vector sets
	 * * an integer that can be converted with strtoul
	 */
	fprintf(stdout, "Purchase operation completed - status: %s\n", status);

out:
	acvp_release_auth(&testid_ctx);
	ACVP_JSON_PUT_NULL(request);
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&response);
	return ret;
}
