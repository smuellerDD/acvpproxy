/* ACVP proxy protocol handler for managing the vendor information
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

#include "errno.h"
#include "string.h"

#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"

static int acvp_vendor_build(const struct def_vendor *def_vendor,
			     struct json_object **json_vendor)
{
	struct json_object *contact_array = NULL, *entry = NULL, *vendor = NULL,
			   *address = NULL;
	int ret = -EINVAL;

	/*
	 * {
	 * "name": "Acme, LLC",
	 * "website": "www.acme.acme",
	 * "emails" : [ "inquiry@acme.acme" ],
	 * "contacts": [{
	 * 	"name": "Jane Smith",
	 *	"emails": ["jane.smith@acme.acme"],
	 *	"phoneNumbers" : [
	 *		{
	 *			"name": "555-555-0001",
	 *			"type" : "fax"
	 *		}, {
	 *			"name": "555-555-0002",
	 *			"type" : "voice"
	 *		}
	 *	],
	 *	"address" : {
	 *		"street" : "123 Main Street",
	 *		"locality" : "Any Town",
	 *		"region" : "AnyState",
	 *		"country" : "USA",
	 *		"postalCode" : "123456"
	 *	}
	 * }]
	 * }
	 */

	address = json_object_new_object();
	CKNULL(address, -ENOMEM);
	CKINT(json_object_object_add(address, "street",
			json_object_new_string(def_vendor->addr_street)));
	CKINT(json_object_object_add(address, "locality",
			json_object_new_string(def_vendor->addr_locality)));
	CKINT(json_object_object_add(address, "region",
			json_object_new_string(def_vendor->addr_region)));
	CKINT(json_object_object_add(address, "country",
			json_object_new_string(def_vendor->addr_country)));
	CKINT(json_object_object_add(address, "postalCode",
			json_object_new_string(def_vendor->addr_zipcode)));

	contact_array = json_object_new_array();
	CKNULL(contact_array, -ENOMEM);
	CKINT(json_object_array_add(contact_array,
			json_object_new_string(def_vendor->contact_email)));

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_object_add(entry, "name",
			json_object_new_string(def_vendor->contact_name)));
	CKINT(json_object_object_add(entry, "emails", contact_array));
	CKINT(json_object_object_add(entry, "address", address));

	contact_array = json_object_new_array();
	CKNULL(contact_array, -ENOMEM);
	CKINT(json_object_array_add(contact_array, entry));

	vendor = json_object_new_object();
	CKNULL(vendor, -ENOMEM);
	CKINT(json_object_object_add(vendor, "name",
			json_object_new_string(def_vendor->vendor_name)));
	CKINT(json_object_object_add(vendor, "website",
			json_object_new_string(def_vendor->vendor_url)));
	CKINT(json_object_object_add(vendor, "contact", contact_array));

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, vendor, "Vendor JSON object");

	*json_vendor = vendor;

	return 0;

out:
	ACVP_JSON_PUT_NULL(contact_array);
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(vendor);
	ACVP_JSON_PUT_NULL(address);
	return ret;
}

static int acvp_vendor_match(const struct def_vendor *def_vendor,
			     struct json_object *json_vendor)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;
	const char *str;
	bool found = false;

	CKINT(json_get_string(json_vendor, "name", &str));
	if (strncmp(def_vendor->vendor_name, str,
		    strlen(def_vendor->vendor_name))) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Vendor name mismatch for vendor ID %u (expected: %s, found: %s)\n",
		       def_vendor->acvp_vendor_id, def_vendor->vendor_name,
		       str);
		ret = -ENOENT;
		goto out;
	}

	CKINT(json_find_key(json_vendor, "contact", &tmp, json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *contact =
				json_object_array_get_idx(tmp, i);
		struct json_object *addr;
		const char *contact_name, *addr_street, *addr_locality;

		CKINT(json_get_string(contact, "name", &contact_name));

		CKINT(json_find_key(contact, "address", &addr,
				    json_type_object));
		CKINT(json_get_string(addr, "street", &addr_street));
		CKINT(json_get_string(addr, "locality", &addr_locality));

		if (!strncmp(def_vendor->addr_street, addr_street,
			     strlen(def_vendor->addr_street)) &&
		    !strncmp(def_vendor->addr_locality, addr_locality,
			     strlen(def_vendor->addr_locality)) &&
		    !strncmp(def_vendor->contact_name, contact_name,
			     strlen(def_vendor->contact_name))) {
			found = true;
			break;
		}
	}

	if (!found) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Vendor address not found for vendor ID %u\n",
		       def_vendor->acvp_vendor_id);
		ret = -ENOENT;
		goto out;
	}

out:
	return ret;
}

/* GET /vendors/<vendorId> */
static int acvp_vendor_validate_one(const struct acvp_testid_ctx *testid_ctx,
				    const struct def_vendor *def_vendor)
{
	struct json_object *resp = NULL, *data = NULL;
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_vendor->acvp_vendor_id));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response (ret: %d): %s\n", ret2,
	       (buf.buf) ? (char *)buf.buf : "(null)");

	CKINT(acvp_store_vendor_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));
	CKINT(acvp_vendor_match(def_vendor, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* POST /vendors */
static int acvp_vendor_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_vendor *def_vendor)
{
	struct json_object *json_vendor = NULL;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));

	/* Build JSON object with the oe specification */
	CKINT(acvp_vendor_build(def_vendor, &json_vendor));

	CKINT(acvp_def_register(testid_ctx, json_vendor, url,
				&def_vendor->acvp_vendor_id));

	/* Write the newly obtained ID to the configuration file */
	CKINT(acvp_def_update_vendor_id(def_vendor));

out:
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}

/* GET /vendors */
static int acvp_vendor_validate_all(const struct acvp_testid_ctx *testid_ctx,
				    struct def_vendor *def_vendor)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *resp = NULL, *data = NULL, *array;
	ACVP_BUFFER_INIT(buf);
	unsigned int i;
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];
	bool found = false;

	CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_vendor_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));

	CKINT(json_find_key(data, "vendors", &array, json_type_array));
	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *vendor =
					json_object_array_get_idx(array, i);

		if (!acvp_vendor_match(def_vendor, vendor)) {
			found = true;
			break;
		}
	}

	if (!found) {
		if (ctx_opts->register_new_vendor) {
			CKINT(acvp_vendor_register(testid_ctx, def_vendor));
		} else {
			ret = -ENOENT;
		}
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

int acvp_vendor_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts;
	const struct acvp_req_ctx *req_details;
	const struct definition *def;
	struct def_vendor *def_vendor;
	struct json_object *json_vendor = NULL;
	int ret = 0;

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
	ctx_opts = &ctx->options;

	if (req_details->dump_register) {
		acvp_vendor_register(testid_ctx, def_vendor);
		goto out;
	}

	if (def_vendor->acvp_vendor_id) {
		if (ctx_opts->register_new_vendor) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Cannot register vendor definition which has already a vendor ID (id %d)\n",
			       def_vendor->acvp_vendor_id);
			return -EINVAL;
		}
		return acvp_vendor_validate_one(testid_ctx, def_vendor);
	} else {
		return acvp_vendor_validate_all(testid_ctx, def_vendor);
	}

out:
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}
