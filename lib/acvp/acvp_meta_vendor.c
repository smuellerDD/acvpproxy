/* ACVP proxy protocol handler for managing the vendor information
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "errno.h"
#include "string.h"

#include "acvp_meta_internal.h"
#include "binhexbin.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"

static int acvp_vendor_build(const struct def_vendor *def_vendor,
			     struct json_object **json_vendor,
			     bool check_ignore_flag)
{
	struct json_object *array = NULL, *entry = NULL, *vendor = NULL,
			   *address = NULL;
	int ret = -EINVAL;

	/*
	 * {
	 * "name": "Acme, LLC",
	 * "website": "www.acme.acme",
	 * "emails" : [ "inquiry@acme.acme" ],
	 * "phoneNumbers" : [
	 *	{
	 *		"number": "555-555-0001",
	 *		"type" : "fax"
	 *	}, {
	 *		"number": "555-555-0002",
	 *		"type" : "voice"
	 *	}
	 * ],
	 * "addresses" [
	 * 	{
	 *		"street1" : "123 Main Street",
	 *		"locality" : "Any Town",
	 *		"region" : "AnyState",
	 *		"country" : "USA",
	 *		"postalCode" : "123456"
	 *	}
	 * ]
	 * }
	 */

	vendor = json_object_new_object();
	CKNULL(vendor, -ENOMEM);

	/* Name, website */
	if (def_vendor->vendor_name &&
	    acvp_check_ignore(check_ignore_flag, def_vendor->vendor_name_i)) {
		CKINT(json_object_object_add(
			vendor, "name",
			json_object_new_string(def_vendor->vendor_name)));
	}

	if (def_vendor->vendor_url &&
	    acvp_check_ignore(check_ignore_flag, def_vendor->vendor_url_i)) {
		CKINT(json_object_object_add(
			vendor, "website",
			json_object_new_string(def_vendor->vendor_url)));
	}

	/* Emails not defined */

	/* Phone numbers not defined */

	/* Addresses */
	address = json_object_new_object();
	CKNULL(address, -ENOMEM);
	if (acvp_check_ignore(check_ignore_flag, def_vendor->addr_street_i)) {
		CKINT(json_object_object_add(
			address, "street1",
			json_object_new_string(def_vendor->addr_street)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_vendor->addr_locality_i)) {
		CKINT(json_object_object_add(
			address, "locality",
			json_object_new_string(def_vendor->addr_locality)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_vendor->addr_region_i)) {
		CKINT(json_object_object_add(
			address, "region",
			!def_vendor->addr_region ? NULL :
			 json_object_new_string(def_vendor->addr_region)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_vendor->addr_country_i)) {
		CKINT(json_object_object_add(
			address, "country",
			json_object_new_string(def_vendor->addr_country)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_vendor->addr_zipcode_i)) {
		CKINT(json_object_object_add(
			address, "postalCode",
			json_object_new_string(def_vendor->addr_zipcode)));
	}

	if (json_object_object_length(address) > 0) {
		if (def_vendor->acvp_vendor_id && def_vendor->acvp_addr_id) {
			const struct acvp_net_ctx *net;
			const struct acvp_net_proto *proto;
			char url[ACVP_NET_URL_MAXLEN];

			CKINT(acvp_get_net(&net));
			proto = net->proto;

			snprintf(url, sizeof(url), "/%s/%s/%u/%s/%u",
				 proto->url_base,
				 NIST_VAL_OP_VENDOR, def_vendor->acvp_vendor_id,
				 NIST_VAL_OP_ADDRESSES,
				 def_vendor->acvp_addr_id);

			CKINT(json_object_object_add(
				address, "url", json_object_new_string(url)));
		}

		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_array_add(array, address));
		address = NULL;
		CKINT(json_object_object_add(vendor, "addresses", array));
		array = NULL;
	}

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, vendor, "Vendor JSON object");

	*json_vendor = vendor;

	return 0;

out:
	ACVP_JSON_PUT_NULL(array);
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(vendor);
	ACVP_JSON_PUT_NULL(address);
	return ret;
}

static int acvp_vendor_match(struct def_vendor *def_vendor,
			     struct json_object *json_vendor)
{
	struct json_object *tmp;
	uint32_t vendor_id;
	unsigned int i;
	int ret, ret2;
	const char *str, *vendorurl;
	bool found = false;

	CKINT(json_get_string(json_vendor, "url", &vendorurl));
	CKINT(acvp_get_trailing_number(vendorurl, &vendor_id));

	CKINT(json_get_string(json_vendor, "name", &str));
	ret = acvp_str_match(def_vendor->vendor_name, str, vendor_id);
	def_vendor->vendor_name_i = !ret;
	ret2 = ret;

	CKINT(json_get_string(json_vendor, "website", &str));
	ret = acvp_str_match(def_vendor->vendor_url, str, vendor_id);
	def_vendor->vendor_url_i = !ret;
	ret2 |= ret;

	CKINT(json_find_key(json_vendor, "addresses", &tmp, json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *contact = json_object_array_get_idx(tmp, i);
		uint32_t id;
		const char *postalcode, *addr_street, *addr_locality,
			   *addr_region, *addr_country;

		CKINT(json_get_string(contact, "postalCode", &postalcode));
		CKINT(json_get_string(contact, "street1", &addr_street));
		CKINT(json_get_string(contact, "locality", &addr_locality));
		ret = json_get_string(contact, "region", &addr_region);
		if (ret)
			addr_region = NULL;
		CKINT(json_get_string(contact, "country", &addr_country));
		CKINT(json_get_string(contact, "url", &str));
		/* Get the oe ID which is the last pathname component */
		CKINT(acvp_get_trailing_number(str, &id));

		def_vendor->addr_street_i =
			!acvp_str_match(def_vendor->addr_street, addr_street,
					vendor_id);
		def_vendor->addr_locality_i =
			!acvp_str_match(def_vendor->addr_locality, addr_locality,
					vendor_id);
		def_vendor->addr_zipcode_i =
			!acvp_str_match(def_vendor->addr_zipcode, postalcode,
					vendor_id);
		def_vendor->addr_region_i =
			!acvp_str_match(def_vendor->addr_region, addr_region,
					vendor_id);
		def_vendor->addr_country_i =
			!acvp_str_match(def_vendor->addr_country, addr_country,
					vendor_id);

		if (def_vendor->addr_street_i &&
		    def_vendor->addr_locality_i &&
		    def_vendor->addr_zipcode_i &&
		    def_vendor->addr_region_i &&
		    def_vendor->addr_country_i) {
			def_vendor->acvp_addr_id = id;
			found = true;
			break;
		}
	}

	if (!found) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Vendor address not found for vendor ID %u\n",
		       vendor_id);
		ret2 |= -ENOENT;
	}

	if (!ret2)
		def_vendor->acvp_vendor_id = vendor_id;

	/*
	 * Return the collected results - if one does not match, the match
	 * fails.
	 */
	ret = ret2;

out:
	return ret;
}

/* GET /vendors/<vendorId> */
static int acvp_vendor_get_match(const struct acvp_testid_ctx *testid_ctx,
				 struct def_vendor *def_vendor,
				 struct json_object **resp,
				 struct json_object **data)
{
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_vendor->acvp_vendor_id));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_vendor_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_req_strip_version(&buf, resp, data));
	CKINT(acvp_vendor_match(def_vendor, *data));

out:
	acvp_free_buf(&buf);
	return ret;
}

/* POST / PUT / DELETE /vendors */
static int acvp_vendor_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_vendor *def_vendor, char *url,
				const unsigned int urllen,
				const enum acvp_http_type type,
				const bool asked)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_vendor = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;

	/* Build JSON object with the vendor specification */
	if (type != acvp_http_delete) {
		CKINT(acvp_vendor_build(def_vendor, &json_vendor, asked));
	}

	if (!req_details->dump_register && !ctx_opts->register_new_vendor &&
	    !asked) {
		if (json_vendor) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_vendor,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}
		if (ask_yes("No module definition found - shall the vendor be registered")) {
			ret = -ENOENT;
			goto out;
		}
	}

	CKINT(acvp_meta_register(testid_ctx, json_vendor, url, urllen,
				 &def_vendor->acvp_vendor_id, type));
	if (req_details->dump_register) {
		goto out;
	}

	CKINT(acvp_register_dump_request(testid_ctx, NIST_VAL_OP_VENDOR,
					 json_vendor));

	/* Fetch address ID */
	CKINT(acvp_vendor_get_match(testid_ctx, def_vendor, &resp,
				    &found_data));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}

static int acvp_vendor_validate_one(const struct acvp_testid_ctx *testid_ctx,
				    struct def_vendor *def_vendor)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *json_vendor = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;
	enum acvp_http_type http_type;
	char url[ACVP_NET_URL_MAXLEN];
	bool asked = false;

	logger_status(LOGGER_C_ANY, "Validating vendor reference %u\n",
		      def_vendor->acvp_vendor_id);

	ret = acvp_vendor_get_match(testid_ctx, def_vendor, &resp, &found_data);

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_VENDOR, ctx_opts,
				       def_vendor->acvp_vendor_id, &http_type);
	if (ret == -ENOENT) {
		CKINT(acvp_vendor_build(def_vendor, &json_vendor,
					!!found_data));
		if (json_vendor) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_vendor,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (found_data) {
			logger_status(
				LOGGER_C_ANY,
				"Data currently on ACVP server: %s\n",
				json_object_to_json_string_ext(
					found_data,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (!ask_yes(
			    "Local meta data differs from ACVP server data - shall the ACVP data base be UPDATED")) {
			http_type = acvp_http_put;
		} else if (
			!ask_yes(
				"Shall the entry be DELETED from the ACVP server data base")) {
			http_type = acvp_http_delete;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Registering operation interrupted\n");
			goto out;
		}

		asked = true;
	} else if (ret) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Conversion from search type to HTTP request type failed for vendor\n");
		goto out;
	} else if (http_type == acvp_http_put) {
		/* Update requested */
		CKINT(acvp_vendor_build(def_vendor, &json_vendor, true));
		if (json_vendor) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_vendor,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (found_data) {
			logger_status(
				LOGGER_C_ANY,
				"Data currently on ACVP server: %s\n",
				json_object_to_json_string_ext(
					found_data,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (ask_yes("Local meta data differs from ACVP server data - shall the ACVP data base be UPDATED")) {
			ret = -ENOENT;
			goto out;
		}
		asked = true;
	} else if (http_type == acvp_http_delete) {
		/* Delete requested */
		if (found_data) {
			logger_status(
				LOGGER_C_ANY,
				"Data currently on ACVP server: %s\n",
				json_object_to_json_string_ext(
					found_data,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (ask_yes("Shall the entry be DELETED from the ACVP server data base")) {
			ret = -ENOENT;
			goto out;
		}
		asked = true;
	}

	if (http_type == acvp_http_none)
		goto out;

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	CKINT(acvp_vendor_register(testid_ctx, def_vendor, url, sizeof(url),
				   http_type, asked));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}

static int acvp_vendor_match_cb(void *private, struct json_object *json_vendor)
{
	struct def_vendor *def_vendor = private;
	int ret;

	ret = acvp_vendor_match(def_vendor, json_vendor);
	/* We found a match */
	if (!ret)
		return EINTR;
	/* We found no match, yet there was no error */
	if (ret == -ENOENT)
		return 0;

	/* We received an error */
	return ret;
}

/* GET /vendors */
static int acvp_vendor_validate_all(const struct acvp_testid_ctx *testid_ctx,
				    struct def_vendor *def_vendor)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN], queryoptions[256], vendorstr[128];

	logger_status(LOGGER_C_ANY,
		      "Searching for vendor reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));

	/* Set a query option consisting of vendor_name */
	CKINT(bin2hex_html(def_vendor->vendor_name,
			   (uint32_t)strlen(def_vendor->vendor_name), vendorstr,
			   sizeof(vendorstr)));
	snprintf(queryoptions, sizeof(queryoptions), "name[0]=contains:%s",
		 vendorstr);
	CKINT(acvp_append_urloptions(queryoptions, url, sizeof(url)));

	CKINT(acvp_paging_get(testid_ctx, url, ACVP_OPTS_SHOW_VENDOR,
			      def_vendor, &acvp_vendor_match_cb));

	/* We found an entry and do not need to do anything */
	if (ret > 0 || opts->show_db_entries) {
		ret = 0;
		goto out;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	CKINT(acvp_vendor_register(testid_ctx, def_vendor, url, sizeof(url),
				   acvp_http_post, false));

out:
	return ret;
}

int acvp_vendor_handle_open_requests(const struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def;
	struct def_vendor *def_vendor;
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Vendor handling: cipher definitions missing\n");
	def_vendor = def->vendor;
	CKNULL_LOG(def_vendor, -EINVAL,
		   "Vendor handling: vendor definitions missing\n");

	CKINT(acvp_def_get_vendor_id(def_vendor));
	ret = acvp_meta_obtain_request_result(testid_ctx,
					      &def_vendor->acvp_vendor_id);
	ret |= acvp_meta_obtain_request_result(testid_ctx,
					       &def_vendor->acvp_addr_id);

	ret |= acvp_def_put_vendor_id(def_vendor);

out:
	return ret;
}

int acvp_vendor_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts;
	const struct acvp_req_ctx *req_details;
	const struct definition *def;
	struct def_vendor *def_vendor;
	struct json_object *json_vendor = NULL;
	int ret = 0, ret2;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Vendor handling: cipher definitions missing\n");
	def_vendor = def->vendor;
	CKNULL_LOG(def_vendor, -EINVAL,
		   "Vendor handling: vendor definitions missing\n");
	CKNULL_LOG(ctx, -EINVAL, "Vendor validation: ACVP context missing\n");
	req_details = &ctx->req_details;
	opts = &ctx->options;

	/* Lock def_vendor */
	CKINT(acvp_def_get_vendor_id(def_vendor));

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT_ULCK(
			acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
		acvp_vendor_register(testid_ctx, def_vendor, url, sizeof(url),
				     acvp_http_post, false);
		goto unlock;
	}

	/* Check if we have an outstanding request */
	ret2 = acvp_meta_obtain_request_result(testid_ctx,
					       &def_vendor->acvp_vendor_id);
	ret2 |= acvp_meta_obtain_request_result(testid_ctx,
						&def_vendor->acvp_addr_id);
	if (ret2) {
		ret = ret2;
		goto unlock;
	}

	if (def_vendor->acvp_vendor_id && !(opts->show_db_entries)) {
		CKINT_ULCK(acvp_vendor_validate_one(testid_ctx, def_vendor));
	} else {
		CKINT_ULCK(acvp_vendor_validate_all(testid_ctx, def_vendor));
	}

unlock:
	ret |= acvp_def_put_vendor_id(def_vendor);
out:
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}
