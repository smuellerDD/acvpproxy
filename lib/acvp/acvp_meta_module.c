/* ACVP proxy protocol handler for managing the module information
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

int acvp_module_type_enum_to_name(const enum def_mod_type env_type,
				  const char **out_string)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(def_mod_type_conversion); i++) {
		if (env_type == def_mod_type_conversion[i].type) {
			*out_string = def_mod_type_conversion[i].type_name;
			return 0;
		}
	}

	return -EINVAL;
}

int acvp_module_type_name_to_enum(const char *str, enum def_mod_type *env_type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(def_mod_type_conversion); i++) {
		if (acvp_find_match(str, def_mod_type_conversion[i].type_name,
				    false)) {
			*env_type = def_mod_type_conversion[i].type;
			return 0;
		}
	}

	return -EINVAL;
}

int acvp_module_oe_type(const enum def_mod_type env_type,
			const char **out_string)
{
	switch (env_type) {
	case MOD_TYPE_SOFTWARE:
	case MOD_TYPE_HARDWARE:
	case MOD_TYPE_FIRMWARE:
	case MOD_TYPE_SOFTWARE_HYBRID:
	case MOD_TYPE_FIRMWARE_HYBRID:
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY, "Wrong OE type provided\n");
		return -EINVAL;
	}

	if (out_string) {
		return acvp_module_type_enum_to_name(env_type, out_string);
	}
	return 0;
}

static int acvp_module_set_oe_type(const enum def_mod_type env_type,
				   struct json_object *entry, const char *key)
{
	int ret;
	const char *type_string;

	CKINT(acvp_module_oe_type(env_type, &type_string));
	CKINT(json_object_object_add(entry, key,
				     json_object_new_string(type_string)));

out:
	return ret;
}

static int acvp_module_description(const struct def_info *def_info, char *str,
				   const size_t str_len)
{
	int ret = 0;

	snprintf(str, str_len, "%s", def_info->module_description);
	if (def_info->impl_description && strlen(def_info->impl_description)) {
		CKINT(acvp_extend_string(
			str, str_len,
			" The following cipher implementation is covered: %s.",
			def_info->impl_description));
	}

out:
	return ret;
}

static int acvp_module_build(const struct def_info *def_info,
			     struct json_object **json_module,
			     bool check_ignore_flag)
{
	struct json_object *entry = NULL, *array = NULL;
	int ret = -EINVAL;
	char url[ACVP_NET_URL_MAXLEN], desc[FILENAME_MAX];

	/*
	 * {
	 *	"name": "ACME ACV Test Module",
	 *	"version": "3.0",
	 *	"type": "Software",
	 *	"vendorUrl": "/acvp/v1/vendors/2",
	 *	"addressUrl": "/acvp/v1/vendors/2/addresses/4",
	 *	"contactUrls": ["/acvp/v1/persons/1" ],
	 *	"description" : "ACME module with more"
	 * }
	 */

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	if (acvp_check_ignore(check_ignore_flag, def_info->module_name_i)) {
		CKINT(json_object_object_add(
			entry, "name",
			json_object_new_string(def_info->module_name)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_info->module_version_i)) {
		CKINT(json_object_object_add(
			entry, "version",
			json_object_new_string(def_info->module_version)));
	}

	if (acvp_check_ignore(check_ignore_flag, def_info->module_type_i)) {
		CKINT(acvp_module_set_oe_type(def_info->module_type, entry,
					      "type"));
	}

	if (acvp_check_ignore(check_ignore_flag, def_info->acvp_vendor_id_i)) {
		CKINT(acvp_create_urlpath(NIST_VAL_OP_VENDOR, url,
					  sizeof(url)));
		CKINT(acvp_extend_string(url, sizeof(url), "/%u",
					 def_info->acvp_vendor_id));
		CKINT(json_object_object_add(entry, "vendorUrl",
					     json_object_new_string(url)));
	}

	if (acvp_check_ignore(check_ignore_flag, def_info->acvp_addr_id_i)) {
		CKINT(acvp_extend_string(url, sizeof(url), "/%s/%u",
					 NIST_VAL_OP_ADDRESSES,
					 def_info->acvp_addr_id));
		CKINT(json_object_object_add(entry, "addressUrl",
					     json_object_new_string(url)));
	}

	if (acvp_check_ignore(check_ignore_flag, def_info->acvp_person_id_i)) {
		size_t person_cnt;

		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "contactUrls", array));

		for (person_cnt = 0; person_cnt < def_info->acvp_person_cnt;
		     person_cnt++) {
			CKINT(acvp_create_urlpath(NIST_VAL_OP_PERSONS, url,
						  sizeof(url)));
			CKINT(acvp_extend_string(
				url, sizeof(url), "/%u",
				def_info->acvp_person_id[person_cnt]));
			CKINT(json_object_array_add(
				array, json_object_new_string(url)));
		}
		array = NULL;
	}

	if (acvp_check_ignore(check_ignore_flag,
			      def_info->module_description_i)) {
		CKINT(acvp_module_description(def_info, desc, sizeof(desc)));
		CKINT(json_object_object_add(entry, "description",
					json_object_new_string(desc)));
	}

	*json_module = entry;

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(array);
	return ret;
}

static int acvp_module_check_id(struct json_object *data, const char *keyword,
				const uint32_t existing_id)
{
	uint32_t id;
	int ret;
	const char *str;

	CKINT(json_get_string(data, keyword, &str));
	/* Get the oe ID which is the last pathname component */
	CKINT(acvp_get_trailing_number(str, &id));

	if (existing_id != id) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "%s ID on ACVP server (%u) does not match our stored vendor ID (%u)\n",
		       keyword, id, existing_id);
		ret = -ENOENT;
		goto out;
	}

out:
	return ret;
}

static int acvp_module_match(struct def_info *def_info,
			     struct json_object *json_module)
{
	struct json_object *tmp;
	uint32_t id = 0, module_id;
	unsigned int i;
	int ret, ret2;
	const char *str, *type_string, *moduleurl;
	char desc[FILENAME_MAX];
	bool not_found = false;

	CKINT(json_get_string(json_module, "url", &moduleurl));
	CKINT(acvp_get_trailing_number(moduleurl, &module_id));

	CKINT(json_get_string(json_module, "name", &str));
	ret = acvp_str_match(def_info->module_name, str, module_id);
	def_info->module_name_i = !ret;
	ret2 = ret;

	CKINT(json_get_string(json_module, "version", &str));
	ret = acvp_str_match(def_info->module_version, str, module_id);
	def_info->module_version_i = !ret;
	ret2 |= ret;

	CKINT(acvp_module_oe_type(def_info->module_type, &type_string));
	CKINT(json_get_string(json_module, "type", &str));
	ret = acvp_str_case_match(type_string, str, def_info->acvp_module_id);
	def_info->module_type_i = !ret;
	ret2 |= ret;

	ret = acvp_module_check_id(json_module, "vendorUrl",
				   def_info->acvp_vendor_id);
	def_info->acvp_vendor_id_i = !ret;
	ret2 |= ret;

	ret = acvp_module_check_id(json_module, "addressUrl",
				   def_info->acvp_addr_id);
	def_info->acvp_addr_id_i = !ret;
	ret2 |= ret;

	CKINT(json_find_key(json_module, "contactUrls", &tmp, json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *contact = json_object_array_get_idx(tmp, i);
		size_t person_cnt;
		bool found_one = false;

		/* Get the ID which is the last pathname component */
		CKINT(acvp_get_id_from_url(json_object_get_string(contact),
					   &id));

		for (person_cnt = 0; person_cnt < def_info->acvp_person_cnt;
		     person_cnt++) {
			if (id == def_info->acvp_person_id[person_cnt]) {
				found_one = true;
				def_info->acvp_person_id_i[person_cnt] = true;
				break;
			}
		}

		if (!found_one)
			not_found = true;
	}

	CKINT(json_get_string(json_module, "description", &str));
	CKINT(acvp_module_description(def_info, desc, sizeof(desc)));
	ret = acvp_str_match(desc, str, def_info->acvp_module_id);
	def_info->module_description_i = !ret;
	ret2 |= ret;

	if (not_found) {
		logger(LOGGER_WARN, LOGGER_C_ANY, "Module ID %u not found\n",
		       module_id);
		ret2 |= -ENOENT;
	}

	if (!ret2)
		def_info->acvp_module_id = module_id;

	ret = ret2;

out:
	return ret;
}

/* GET /modules/<moduleId> */
static int acvp_module_get_match(const struct acvp_testid_ctx *testid_ctx,
				 struct def_info *def_info,
				 struct json_object **resp,
				 struct json_object **data)
{
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_module_id));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_module_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_req_strip_version(&buf, resp, data));
	CKINT(acvp_module_match(def_info, *data));

out:
	acvp_free_buf(&buf);
	return ret;
}

/* POST / PUT / DELETE /modules */
static int acvp_module_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_info *def_info, char *url,
				const unsigned int urllen,
				const enum acvp_http_type type,
				const bool asked)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_info = NULL;
	int ret;

	/* Build JSON object with the oe specification */
	if (type != acvp_http_delete) {
		CKINT(acvp_module_build(def_info, &json_info, asked));
	}

	if (!req_details->dump_register && !ctx_opts->register_new_module &&
	    !asked) {
		if (json_info) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_info,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}
		if (ask_yes("No module definition found - shall the module be registered")) {
			ret = -ENOENT;
			goto out;
		}
	}

	CKINT(acvp_meta_register(testid_ctx, json_info, url, urllen,
				 &def_info->acvp_module_id, type));

	if (req_details->dump_register) {
		goto out;
	}

	CKINT(acvp_register_dump_request(testid_ctx, NIST_VAL_OP_MODULE,
					 json_info));

out:
	ACVP_JSON_PUT_NULL(json_info);
	return ret;
}

static int acvp_module_validate_one(const struct acvp_testid_ctx *testid_ctx,
				    struct def_info *def_info)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *json_info = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;
	enum acvp_http_type http_type;
	char url[ACVP_NET_URL_MAXLEN];
	bool asked = false;

	logger_status(LOGGER_C_ANY, "Validating module reference %u\n",
		      def_info->acvp_module_id);

	ret = acvp_module_get_match(testid_ctx, def_info, &resp, &found_data);

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_MODULE, ctx_opts,
				       def_info->acvp_module_id, &http_type);
	if (ret == -ENOENT) {
		CKINT(acvp_module_build(def_info, &json_info, !!found_data));
		if (json_info) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_info,
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
		       "Conversion from search type to HTTP request type failed for module\n");
		goto out;
	} else if (http_type == acvp_http_put) {
		/* Update requested */
		CKINT(acvp_module_build(def_info, &json_info, true));
		if (json_info) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_info,
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

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_module_register(testid_ctx, def_info, url, sizeof(url),
				   http_type, asked));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_info);
	return ret;
}

static int acvp_module_match_cb(void *private, struct json_object *json_vendor)
{
	struct def_info *def_info = private;
	int ret;

	ret = acvp_module_match(def_info, json_vendor);

	/* We found a match */
	if (!ret)
		return EINTR;
	/* We found no match, yet there was no error */
	if (ret == -ENOENT)
		return 0;

	/* We received an error */
	return ret;
}

/* GET /modules */
static int acvp_module_validate_all(const struct acvp_testid_ctx *testid_ctx,
				    struct def_info *def_info)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN], queryoptions[900], modulestr[800];

	logger_status(LOGGER_C_ANY,
		      "Searching for module reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));

	/* Set a query option consisting of module name */
	CKINT(bin2hex_html(def_info->module_name,
			   (uint32_t)strlen(def_info->module_name), modulestr,
			   sizeof(modulestr)));
	snprintf(queryoptions, sizeof(queryoptions), "name[0]=contains:%s",
		 modulestr);
	CKINT(acvp_append_urloptions(queryoptions, url, sizeof(url)));

	CKINT(acvp_paging_get(testid_ctx, url, ACVP_OPTS_SHOW_MODULE, def_info,
			      &acvp_module_match_cb));

	/* We found an entry and do not need to do anything */
	if (ret > 0 || opts->show_db_entries) {
		ret = 0;
		goto out;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_module_register(testid_ctx, def_info, url, sizeof(url),
				   acvp_http_post, false));

out:
	return ret;
}

int acvp_module_handle_open_requests(const struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def;
	struct def_info *def_info;
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Vendor handling: cipher definitions missing\n");
	def_info = def->info;
	CKNULL_LOG(def_info, -EINVAL,
		   "Module handling: module definitions missing\n");

	CKINT(acvp_def_get_module_id(def_info));

	ret = acvp_meta_obtain_request_result(testid_ctx,
					      &def_info->acvp_module_id);

	ret |= acvp_def_put_module_id(def_info);

out:
	return ret;
}

int acvp_module_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	struct def_info *def_info;
	struct def_vendor *def_vendor;
	struct def_person *def_person;
	struct json_object *json_module = NULL;
	size_t person_cnt = 0;
	int ret = 0;
	bool invalid = false;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Module handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Module handling: cipher definitions missing\n");
	def_info = def->info;
	CKNULL_LOG(def_info, -EINVAL,
		   "Module handling: module definitions missing\n");
	def_vendor = def->vendor;
	CKNULL_LOG(def_vendor, -EINVAL,
		   "Module handling: vendor definitions missing\n");
	CKNULL_LOG(ctx, -EINVAL, "Vendor validation: ACVP context missing\n");
	req_details = &ctx->req_details;
	opts = &ctx->options;

	/* Static entry */
	person_cnt++;
	/* List entries */
	list_for_each(def_person, &def_vendor->person.list, list)
		person_cnt++;

	def_info->acvp_person_id = calloc(person_cnt, sizeof(uint32_t));
	CKNULL(def_info->acvp_person_id, -ENOMEM);
	def_info->acvp_person_id_i = calloc(person_cnt, sizeof(uint8_t));
	CKNULL(def_info->acvp_person_id, -ENOMEM);
	def_info->acvp_person_cnt = person_cnt;

	/* Static entry */
	person_cnt = 0;
	def_info->acvp_person_id[person_cnt] =
		def_vendor->person.acvp_person_id;
	person_cnt++;
	/* List entries */
	list_for_each(def_person, &def_vendor->person.list, list) {
		def_info->acvp_person_id[person_cnt] =
			def_person->acvp_person_id;
		person_cnt++;
	}

	def_info->acvp_vendor_id = def_vendor->acvp_vendor_id;
	def_info->acvp_addr_id = def_vendor->acvp_addr_id;

	invalid |= !acvp_valid_id(def_vendor->acvp_vendor_id);
	for (person_cnt = 0; person_cnt < def_info->acvp_person_cnt;
	     person_cnt++)
		invalid |= !acvp_valid_id(def_info->acvp_person_id[person_cnt]);

	invalid |= !acvp_valid_id(def_vendor->acvp_addr_id);

	if (invalid) {
		logger(req_details->dump_register ? LOGGER_WARN : LOGGER_ERR,
		       LOGGER_C_ANY,
		       "Module handling: vendor / person / address ID missing\n");

		ret = -EINVAL;
		goto out;
	}

	/* Lock def_info */
	CKINT(acvp_def_get_module_id(def_info));

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
		acvp_module_register(testid_ctx, def_info, url, sizeof(url),
				     acvp_http_post, false);
		goto unlock;
	}

	/* Check if we have an outstanding request */
	CKINT_ULCK(acvp_meta_obtain_request_result(testid_ctx,
						   &def_info->acvp_module_id));

	if (def_info->acvp_module_id && !(opts->show_db_entries)) {
		CKINT_ULCK(acvp_module_validate_one(testid_ctx, def_info));
	} else {
		CKINT_ULCK(acvp_module_validate_all(testid_ctx, def_info));
	}

unlock:
	ret |= acvp_def_put_module_id(def_info);
out:
	ACVP_JSON_PUT_NULL(json_module);
	return ret;
}
