/* ACVP proxy protocol handler for managing the person information
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

static int acvp_person_build(const struct def_vendor *def_vendor,
			     struct json_object **json_person)
{
	struct json_object *array = NULL, *entry = NULL, *person = NULL,
			   *phone = NULL;
	char vendor_url[ACVP_NET_URL_MAXLEN];
	int ret = -EINVAL;

	/*
	 * {
	 *	"fullName": "Jane Smith",
	 *	"vendorUrl" : "/acvp/v1/vendors/2"
	 *	"emails": ["jane.smith@acme.acme"],
	 *	"phoneNumbers" : [
	 *	{
	 *		"number": "555-555-0001",
	 *		"type" : "fax"
	 *	}, {
	 *		"number": "555-555-0002",
	 *		"type" : "voice"
	 *	}
	 *	]
	 *}
	 */

	person = json_object_new_object();
	CKNULL(person, -ENOMEM);

	/* Name */
	CKINT(json_object_object_add(person, "fullName",
			json_object_new_string(def_vendor->contact_name)));

	/* Reference to Vendor definition */
	CKINT(acvp_create_urlpath(NIST_VAL_OP_VENDOR, vendor_url,
				  sizeof(vendor_url)));
	CKINT(acvp_extend_string(vendor_url, sizeof(vendor_url), "/%u",
				 def_vendor->acvp_vendor_id));
	CKINT(json_object_object_add(person, "vendorUrl",
			json_object_new_string(vendor_url)));

	/* Emails */
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_array_add(array,
			json_object_new_string(def_vendor->contact_email)));
	CKINT(json_object_object_add(person, "emails", array));
	array = NULL;

	/* Phone numbers */
	phone = json_object_new_object();
	CKNULL(phone, -ENOMEM);
	CKINT(json_object_object_add(phone, "number",
			json_object_new_string(def_vendor->contact_phone)));
	CKINT(json_object_object_add(phone, "type",
			json_object_new_string("voice")));
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_array_add(array, phone));
	phone = NULL;
	CKINT(json_object_object_add(person, "phoneNumbers", array));
	array = NULL;

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, person, "Vendor JSON object");

	*json_person = person;

	return 0;

out:
	ACVP_JSON_PUT_NULL(array);
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(person);
	ACVP_JSON_PUT_NULL(phone);
	return ret;
}

static int acvp_person_match(struct def_vendor *def_vendor,
			     struct json_object *json_vendor)
{
	struct json_object *tmp;
	uint32_t organizationurl_id, person_id;
	unsigned int i;
	int ret;
	const char *personurl = NULL, *name = NULL, *organizationurl = NULL;
	bool found = false;

	CKINT(json_get_string(json_vendor, "url", &personurl));
	CKINT(acvp_get_trailing_number(personurl, &person_id));

	CKINT(json_get_string(json_vendor, "fullName", &name));

	/* No error handling as we check for the NULL value below */
	json_get_string(json_vendor, "vendorUrl", &organizationurl);
	CKINT(acvp_get_trailing_number(organizationurl, &organizationurl_id));

	if (strncmp(def_vendor->contact_name, name,
		    strlen(def_vendor->contact_name)) ||
	    organizationurl_id != def_vendor->acvp_vendor_id) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Contact name mismatch for contact ID %u (expected: %s, found: %s, vendor ID %u)\n",
		      person_id, def_vendor->contact_name, name,
		      def_vendor->acvp_vendor_id);
		ret = -ENOENT;
		goto out;
	}

	CKINT(json_find_key(json_vendor, "emails", &tmp, json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *email =
				json_object_array_get_idx(tmp, i);

		if (!strncmp(def_vendor->contact_email,
			     json_object_get_string(email),
			     strlen(def_vendor->contact_email))) {
			found = true;
			break;
		}
	}

	if (!found) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Person email address not found for person ID %u\n",
		       def_vendor->acvp_person_id);
		ret = -ENOENT;
		goto out;
	}

	CKINT(json_find_key(json_vendor, "phoneNumbers", &tmp,
			    json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *number_def =
				json_object_array_get_idx(tmp, i);
		const char *number, *type;

		CKINT(json_get_string(number_def, "number", &number));
		CKINT(json_get_string(number_def, "type", &type));

		if (!strncmp(def_vendor->contact_phone, number,
			     strlen(def_vendor->contact_phone)) &&
		    !strncmp("voice", type, 5)) {
			found = true;
			break;
		}
	}

	if (!found) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Person phone number not found for person ID %u\n",
		       def_vendor->acvp_person_id);
		ret = -ENOENT;
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Person found\n");
	def_vendor->acvp_person_id = person_id;

out:
	return ret;
}

/* GET /persons/<personId> */
static int acvp_person_get_match(const struct acvp_testid_ctx *testid_ctx,
				 struct def_vendor *def_vendor,
				 struct json_object **resp,
				 struct json_object **data)
{
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_vendor->acvp_person_id));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_person_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_req_strip_version(&buf, resp, data));
	CKINT(acvp_person_match(def_vendor, *data));

out:
	acvp_free_buf(&buf);
	return ret;
}

/* POST / PUT / DELETE /persons */
static int acvp_person_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_vendor *def_vendor,
				char *url, unsigned int urllen,
				enum acvp_http_type type, bool asked)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_person = NULL;
	int ret;

	/* Build JSON object with the vendor specification */
	if (type != acvp_http_delete) {
		CKINT(acvp_person_build(def_vendor, &json_person));
	}

	if (!req_details->dump_register &&
	    !ctx_opts->register_new_vendor &&
	    !asked) {
		if (json_person) {
			logger_status(LOGGER_C_ANY,
				      "Data to be registered: %s\n",
				      json_object_to_json_string_ext(json_person,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		}
		if (ask_yes("No module definition found - shall the person be registered")) {
			ret = -ENOENT;
			goto out;
		}
	}

	CKINT(acvp_meta_register(testid_ctx, json_person, url, urllen,
				 &def_vendor->acvp_person_id, type));

out:
	ACVP_JSON_PUT_NULL(json_person);
	return ret;
}

static int acvp_person_validate_one(const struct acvp_testid_ctx *testid_ctx,
				    struct def_vendor *def_vendor)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *json_person = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;
	enum acvp_http_type http_type;
	char url[ACVP_NET_URL_MAXLEN];
	bool asked = false;

	logger_status(LOGGER_C_ANY, "Validating person reference %u\n",
		      def_vendor->acvp_person_id);

	ret = acvp_person_get_match(testid_ctx, def_vendor, &resp, &found_data);

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_PERSON,
				       ctx_opts, def_vendor->acvp_person_id,
				       &http_type);
	if (ret == -ENOENT) {
		CKINT(acvp_person_build(def_vendor, &json_person));
		if (json_person) {
			logger_status(LOGGER_C_ANY,
				      "Data to be registered: %s\n",
				      json_object_to_json_string_ext(json_person,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (found_data) {
			logger_status(LOGGER_C_ANY,
				      "Data currently on ACVP server: %s\n",
				      json_object_to_json_string_ext(found_data,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (!ask_yes("Local meta data differs from ACVP server data - shall the ACVP data base be UPDATED")) {
			http_type = acvp_http_put;
		} else if (!ask_yes("Shall the entry be DELETED from the ACVP server data base")) {
			http_type = acvp_http_delete;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Registering operation interrupted\n");
			goto out;
		}

		asked = true;
	} else if (ret) {
		  logger(LOGGER_ERR, LOGGER_C_ANY,
			 "Conversion from search type to HTTP request type failed for person\n");
		  goto out;
	} else if (http_type == acvp_http_put) {
		/* Update requested */
		CKINT(acvp_person_build(def_vendor, &json_person));
		if (json_person) {
			logger_status(LOGGER_C_ANY,
				      "Data to be registered: %s\n",
				      json_object_to_json_string_ext(json_person,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (found_data) {
			logger_status(LOGGER_C_ANY,
				      "Data currently on ACVP server: %s\n",
				      json_object_to_json_string_ext(found_data,
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
			logger_status(LOGGER_C_ANY,
				      "Data currently on ACVP server: %s\n",
				      json_object_to_json_string_ext(found_data,
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

	CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, sizeof(url)));
	CKINT(acvp_person_register(testid_ctx, def_vendor, url, sizeof(url),
				   http_type, asked));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_person);
	return ret;
}

static int acvp_person_match_cb(void *private, struct json_object *json_vendor)
{
	struct def_vendor *def_vendor = private;
	int ret;

	ret = acvp_person_match(def_vendor, json_vendor);

	/* We found a match */
	if (!ret)
		return EINTR;
	/* We found no match, yet there was no error */
	if (ret == -ENOENT)
		return 0;

	/* We received an error */
	return ret;
}

/* GET /persons */
static int acvp_person_validate_all(const struct acvp_testid_ctx *testid_ctx,
				    struct def_vendor *def_vendor)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN], queryoptions[256], personstr[128];

	logger_status(LOGGER_C_ANY,
		      "Searching for person reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, sizeof(url)));

	/* Set a query option consisting of contact name */
	CKINT(bin2hex_html(def_vendor->contact_name,
			   (uint32_t)strlen(def_vendor->contact_name),
			   personstr, sizeof(personstr)));
	snprintf(queryoptions, sizeof(queryoptions), "fullName[0]=contains:%s",
		 personstr);
	CKINT(acvp_append_urloptions(queryoptions, url, sizeof(url)));

	CKINT(acvp_paging_get(testid_ctx, url, ACVP_OPTS_SHOW_PERSON,
			      def_vendor, &acvp_person_match_cb));

	/* We found an entry and do not need to do anything */
	if (ret > 0 || opts->show_db_entries) {
		ret = 0;
		goto out;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, sizeof(url)));
	CKINT(acvp_person_register(testid_ctx, def_vendor, url,
				   sizeof(url), acvp_http_post, false));

out:
	return ret;
}

int acvp_person_handle_open_requests(const struct acvp_testid_ctx *testid_ctx)
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
					      &def_vendor->acvp_person_id);

	ret |= acvp_def_put_vendor_id(def_vendor);

out:
	return ret;
}

int acvp_person_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct acvp_opts_ctx *opts;
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
	opts = &ctx->options;

	/* Lock def_vendor */
	CKINT(acvp_def_get_person_id(def_vendor));

	if (!req_details->dump_register &&
	    !acvp_valid_id(def_vendor->acvp_vendor_id)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No ACVP vendor ID present to which a person contact can be linked to\n");
		ret = -EINVAL;
		goto unlock;
	}

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT_ULCK(acvp_create_url(NIST_VAL_OP_PERSONS, url,
					   sizeof(url)));
		acvp_person_register(testid_ctx, def_vendor, url, sizeof(url),
				     acvp_http_post, false);
		goto unlock;
	}

	/* Check if we have an outstanding request */
	CKINT_ULCK(acvp_meta_obtain_request_result(testid_ctx,
						   &def_vendor->acvp_person_id));

	if (def_vendor->acvp_person_id && !(opts->show_db_entries)) {
		CKINT_ULCK(acvp_person_validate_one(testid_ctx, def_vendor));
	} else {
		CKINT_ULCK(acvp_person_validate_all(testid_ctx, def_vendor));
	}

unlock:
	ret |= acvp_def_put_person_id(def_vendor);
out:
	ACVP_JSON_PUT_NULL(json_vendor);
	return ret;
}
