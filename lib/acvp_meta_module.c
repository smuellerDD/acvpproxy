/* ACVP proxy protocol handler for managing the module information
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

int acvp_module_oe_type(enum def_mod_type env_type, const char **out_string)
{
	const char *type_string;

	switch (env_type) {
	case MOD_TYPE_SOFTWARE:
		type_string = "Software";
		break;
	case MOD_TYPE_HARDWARE:
		type_string = "Hardware";
		break;
	case MOD_TYPE_FIRMWARE:
		type_string = "Firmware";
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY, "Wrong OE type provided\n");
		return -EINVAL;
	};

	if (out_string)
		*out_string = type_string;

	return 0;
}

static int acvp_module_set_oe_type(enum def_mod_type env_type,
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

static int acvp_module_description(const struct def_info *def_info,
				   char *str, size_t str_len)
{
	int ret = 0;

	snprintf(str, str_len, "%s", def_info->module_description);
	if (def_info->impl_description) {
		CKINT(acvp_extend_string(str, str_len,
					 " The following cipher implementation is covered: %s.",
					 def_info->impl_description));
	}

out:
	return ret;
}

static int acvp_module_build(const struct def_info *def_info,
			     struct json_object **json_module)
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
	CKINT(json_object_object_add(entry, "name",
			json_object_new_string(def_info->module_name)));
	CKINT(json_object_object_add(entry, "version",
			json_object_new_string(def_info->module_version)));
	CKINT(acvp_module_set_oe_type(def_info->module_type, entry, "type"));

	CKINT(acvp_create_urlpath(NIST_VAL_OP_VENDOR, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_vendor_id));
	CKINT(json_object_object_add(entry, "vendorUrl",
				     json_object_new_string(url)));

	CKINT(acvp_extend_string(url, sizeof(url), "/%s/%u",
				 NIST_VAL_OP_ADDRESSES,
				 def_info->acvp_addr_id));
	CKINT(json_object_object_add(entry, "addressUrl",
				     json_object_new_string(url)));

	CKINT(acvp_create_urlpath(NIST_VAL_OP_PERSONS, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_person_id));
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_array_add(array, json_object_new_string(url)));
	CKINT(json_object_object_add(entry, "contactUrls", array));
	array = NULL;

	CKINT(acvp_module_description(def_info, desc, sizeof(desc)));
	CKINT(json_object_object_add(entry, "description",
				     json_object_new_string(desc)));

	*json_module = entry;

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(array);
	return ret;
}

static int acvp_module_check_id(struct json_object *data, const char *keyword,
				uint32_t existing_id)
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
	int ret;
	const char *str, *type_string, *moduleurl;
	char desc[FILENAME_MAX];
	bool found = false;

	CKINT(json_get_string(json_module, "url", &moduleurl));
	CKINT(acvp_get_trailing_number(moduleurl, &module_id));

	CKINT(json_get_string(json_module, "name", &str));
	CKINT(acvp_str_match(def_info->module_name, str,
			     def_info->acvp_module_id));

	CKINT(json_get_string(json_module, "version", &str));
	CKINT(acvp_str_match(def_info->module_version, str,
			     def_info->acvp_module_id));

	CKINT(acvp_module_oe_type(def_info->module_type, &type_string));
	CKINT(json_get_string(json_module, "type", &str));
	CKINT(acvp_str_match(type_string, str, def_info->acvp_module_id));

	CKINT(acvp_module_check_id(json_module, "vendorUrl",
				   def_info->acvp_vendor_id));
	CKINT(acvp_module_check_id(json_module, "addressUrl",
				   def_info->acvp_addr_id));

	CKINT(json_find_key(json_module, "contactUrls", &tmp, json_type_array));
	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *contact =
				json_object_array_get_idx(tmp, i);

		/* Get the oe ID which is the last pathname component */
		CKINT(acvp_get_id_from_url(json_object_get_string(contact),
					   &id));

		if (id == def_info->acvp_person_id) {
			found = true;
			break;
		}
	}

	CKINT(json_get_string(json_module, "description", &str));
	CKINT(acvp_module_description(def_info, desc, sizeof(desc)));
	CKINT(acvp_str_match(desc, str, def_info->acvp_module_id));

	if (!found) {
		logger(LOGGER_WARN, LOGGER_C_ANY, "Module ID %u not found\n",
		       module_id);
		ret = -ENOENT;
		goto out;
	}

	def_info->acvp_module_id = module_id;

out:
	return ret;
}

/* GET /modules/<moduleId> */
static int acvp_module_get_match(const struct acvp_testid_ctx *testid_ctx,
				 struct def_info *def_info)
{
	struct json_object *resp = NULL, *data = NULL;
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

	CKINT(acvp_req_strip_version(&buf, &resp, &data));
	CKINT(acvp_module_match(def_info, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* POST / PUT / DELETE /modules */
static int acvp_module_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_info *def_info,
				char *url, unsigned int urllen,
				enum acvp_http_type type)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_info = NULL;
	int ret;

	/* Build JSON object with the oe specification */
	if (type != acvp_http_delete) {
		CKINT(acvp_module_build(def_info, &json_info));
	}

	if (!req_details->dump_register && !ctx_opts->register_new_module) {
		if (json_info) {
			logger_status(LOGGER_C_ANY,
				      "Data to be registered: %s\n",
				      json_object_to_json_string_ext(json_info,
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
	int ret;
	enum acvp_http_type http_type;
	char url[ACVP_NET_URL_MAXLEN];

	logger_status(LOGGER_C_ANY, "Validating module reference %u\n",
		      def_info->acvp_module_id);

	ret = acvp_module_get_match(testid_ctx, def_info);

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_MODULE,
				       ctx_opts, def_info->acvp_module_id,
				       &http_type);
	if (ret == -ENOENT) {
		CKINT(acvp_module_build(def_info, &json_info));
		if (json_info) {
			logger_status(LOGGER_C_ANY,
				      "Data to be registered: %s\n",
				      json_object_to_json_string_ext(json_info,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		}

		if (!ask_yes("Local meta data differs from ACVP server data - shall the ACVP data base be UPDATED")) {
			http_type = acvp_http_put;
		} else if (!ask_yes("Local meta data differs from ACVP server data - shall the ACVP data base be DELETED")) {
			http_type = acvp_http_delete;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Registering operation interrupted\n");
			goto out;
		}
	} else if (ret) {
		  logger(LOGGER_ERR, LOGGER_C_ANY,
			 "Conversion from search type to HTTP request type failed for module\n");
		  goto out;
	}

	if (http_type == acvp_http_none)
		goto out;

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_module_register(testid_ctx, def_info, url, sizeof(url),
				   http_type));

out:
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
	int ret;
	char url[ACVP_NET_URL_MAXLEN], queryoptions[256], modulestr[128];

	logger_status(LOGGER_C_ANY,
		      "Searching for module reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));

	/* Set a query option consisting of module name */
	CKINT(bin2hex_html(def_info->module_name,
			   (uint32_t)strlen(def_info->module_name),
			   modulestr, sizeof(modulestr)));
	snprintf(queryoptions, sizeof(queryoptions), "name[0]=contains:%s",
		 modulestr);
	CKINT(acvp_append_urloptions(queryoptions, url, sizeof(url)));

	CKINT(acvp_paging_get(testid_ctx, url, def_info,
			      &acvp_module_match_cb));

	/* We found an entry and do not need to do anything */
	if (ret > 0) {
		ret = 0;
		goto out;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_module_register(testid_ctx, def_info, url,
				   sizeof(url), acvp_http_post));

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
	const struct definition *def;
	struct def_info *def_info;
	struct def_vendor *def_vendor;
	struct json_object *json_module = NULL;
	int ret = 0;

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

	def_info->acvp_vendor_id = def_vendor->acvp_vendor_id;
	def_info->acvp_person_id = def_vendor->acvp_person_id;
	def_info->acvp_addr_id = def_vendor->acvp_addr_id;

	if (!acvp_valid_id(def_vendor->acvp_vendor_id) ||
	    !acvp_valid_id(def_vendor->acvp_person_id) ||
	    !acvp_valid_id(def_vendor->acvp_addr_id)) {
		logger(req_details->dump_register ? LOGGER_WARN : LOGGER_ERR,
		       LOGGER_C_ANY, "Module handling: vendor / person / address ID missing\n");

		ret = -EINVAL;
		goto out;
	}

	/* Lock def_info */
	CKINT(acvp_def_get_module_id(def_info));

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
		acvp_module_register(testid_ctx, def_info, url, sizeof(url),
				     acvp_http_post);
		goto unlock;
	}

	/* Check if we have an outstanding request */
	CKINT_ULCK(acvp_meta_obtain_request_result(testid_ctx,
						   &def_info->acvp_module_id));

	if (def_info->acvp_module_id) {
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
