/* ACVP proxy protocol handler for managing the module information
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

int acvp_module_oe_type(enum def_mod_type env_type, const char **out_string)
{
	const char *type_string;

	switch(env_type) {
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

static int acvp_module_build(const struct def_info *def_info,
			     struct json_object **json_module)
{
	struct json_object *entry = NULL;
	int ret = -EINVAL;
	char vendorurl[ACVP_NET_URL_MAXLEN];

	/*
	 * {
	 *	"name": "ACME ACV Test Module",
	 *	"version": "3.0",
	 *	"type": "Software",
	 *	"vendorUrl": "/acvp/v1/vendors/2",
	 *	"implementationDescription" : "ACME test module with more bells and whistles."
	 * }
	 */

	snprintf(vendorurl, sizeof(vendorurl), "/%s/%s/%u", NIST_VAL_CTX,
		 NIST_VAL_OP_VENDOR, def_info->acvp_vendor_id);

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_object_add(entry, "name",
			json_object_new_string(def_info->module_name)));
	CKINT(json_object_object_add(entry, "version",
			json_object_new_string(def_info->module_version)));
	CKINT(acvp_module_set_oe_type(def_info->module_type, entry, "type"));
	CKINT(json_object_object_add(entry, "vendorUrl",
				     json_object_new_string(vendorurl)));
	CKINT(json_object_object_add(entry, "implementationDescription",
			json_object_new_string(def_info->module_description)));

	*json_module = entry;

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

static int acvp_module_match(const struct def_info *def_info,
			     struct json_object *json_module)
{
	int ret;
	const char *str, *type_string;

	CKINT(json_get_string(json_module, "name", &str));
	if (strncmp(def_info->module_name, str,
		    strlen(def_info->module_name))) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Module name mismatch for module ID %u (expected: %s, found: %s)\n",
		       def_info->acvp_module_id, def_info->module_name,
		       str);
		ret = -ENOENT;
		goto out;
	}

	CKINT(json_get_string(json_module, "version", &str));
	if (strncmp(def_info->module_version, str,
		    strlen(def_info->module_version))) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Module name mismatch for module ID %u (expected: %s, found: %s)\n",
		       def_info->acvp_module_id, def_info->module_version,
		       str);
		ret = -ENOENT;
		goto out;
	}

	CKINT(acvp_module_oe_type(def_info->module_type, &type_string));
	CKINT(json_get_string(json_module, "type", &str));
	if (strncmp(type_string, str, strlen(type_string))) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Module name mismatch for module ID %u (expected: %s, found: %s)\n",
		       def_info->acvp_module_id, type_string, str);
		ret = -ENOENT;
		goto out;
	}

out:
	return ret;
}

/* GET /modules/<moduleId> */
static int acvp_module_validate_one(const struct acvp_testid_ctx *testid_ctx,
				    const struct def_info *def_info)
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

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));
	CKINT(acvp_module_match(def_info, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* POST /modules */
static int acvp_module_register(const struct acvp_testid_ctx *testid_ctx,
				struct def_info *def_info)
{
	struct json_object *json_info = NULL;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));

	/* Build JSON object with the oe specification */
	CKINT(acvp_module_build(def_info, &json_info));

	CKINT(acvp_def_register(testid_ctx, json_info, url,
				&def_info->acvp_module_id));

	/* Write the newly obtained ID to the configuration file */
	CKINT(acvp_def_update_module_id(def_info));

out:
	ACVP_JSON_PUT_NULL(json_info);
	return ret;
}

/* GET /modules */
static int acvp_module_validate_all(const struct acvp_testid_ctx *testid_ctx,
				    struct def_info *def_info)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *resp = NULL, *data = NULL, *array;
	ACVP_BUFFER_INIT(buf);
	unsigned int i;
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];
	bool found = false;

	CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_module_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));

	CKINT(json_find_key(data, "modules", &array, json_type_array));
	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *module =
					json_object_array_get_idx(array, i);

		if (!acvp_module_match(def_info, module)) {
			found = true;
			break;
		}
	}

	if (!found) {
		if (ctx_opts->register_new_module) {
			CKINT(acvp_module_register(testid_ctx, def_info));
		} else {
			ret = -ENOENT;
		}
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

int acvp_module_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct acvp_opts_ctx *ctx_opts;
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
	ctx_opts = &ctx->options;

	if (!def_vendor->acvp_vendor_id) {
		logger(req_details->dump_register ? LOGGER_WARN : LOGGER_ERR,
		       LOGGER_C_ANY, "Module handling: vendor ID missing\n");

		if (!req_details->dump_register)
			return -EINVAL;
	}

	def_info->acvp_vendor_id = def_vendor->acvp_vendor_id;

	if (req_details->dump_register) {
		acvp_module_register(testid_ctx, def_info);
		goto out;
	}

	if (def_info->acvp_module_id) {
		if (ctx_opts->register_new_module) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Cannot register module definition which has already a module ID (id %d)\n",
			       def_info->acvp_module_id);
			return -EINVAL;
		}
		CKINT(acvp_module_validate_one(testid_ctx, def_info));
	} else {
		CKINT(acvp_module_validate_all(testid_ctx, def_info));
	}

out:
	ACVP_JSON_PUT_NULL(json_module);
	return ret;
}
