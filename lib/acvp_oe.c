/* ACVP proxy protocol handler for managing the operational env information
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

enum acvp_oe_dep_types {
	ACVP_OE_DEP_TYPE_SW,
	ACVP_OE_DEP_TYPE_PROC,
};

static int acvp_oe_build_dep_proc(const struct def_oe *def_oe,
				  struct json_object **json_oe)
{
	struct json_object *dep = NULL;
	int ret = -EINVAL;

	/*
	 * {
	 *     "type" : "processor",
	 *     "manufacturer" : "Intel",
	 *     "family" : "ARK",
	 *     "name" : "Xeon",
	 *     "series" : "5100",
	 *     "features" : [ "rdrand" ]
	 * }
	 */

	dep = json_object_new_object();
	CKNULL(dep, -ENOMEM);
	CKINT(json_object_object_add(dep, "type",
			json_object_new_string("processor")));
	CKINT(json_object_object_add(dep, "manufactuer",
			json_object_new_string(def_oe->manufacturer)));
	CKINT(json_object_object_add(dep, "family",
			json_object_new_string(def_oe->proc_family)));
	CKINT(json_object_object_add(dep, "name",
			json_object_new_string(def_oe->proc_name)));
	CKINT(json_object_object_add(dep, "series",
			json_object_new_string(def_oe->proc_series)));

	//TODO what to add?
	CKINT(json_object_object_add(dep, "description",
			json_object_new_string("TOBEDEFINED")));

	//TODO re-add features
#if 0
	if (def_oe->features) {
		struct json_object *feature_array = json_object_new_array();
		unsigned int i;

		CKNULL(feature_array, -ENOMEM);
		CKINT(json_object_object_add(dep, "features", feature_array));

		for (i = 0; i < ARRAY_SIZE(acvp_features); i++) {
			if (def_oe->features & acvp_features[i].feature) {
				CKINT(json_object_array_add(feature_array,
					json_object_new_string(
						acvp_features[i].name)));
			}
		}
	}
#endif

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, dep, "Vendor JSON object");

	*json_oe = dep;

	return 0;

out:
	ACVP_JSON_PUT_NULL(dep);
	return ret;
}

static int acvp_oe_build_dep_sw(const struct def_oe *def_oe,
				struct json_object **json_oe)
{
	struct json_object *dep = NULL;
	int ret = -EINVAL;

	/*
	 * {
	 *     "type" : "software",
	 *     "name" : "Linux 3.1",
	 *     "cpe"  : "cpe-2.3:o:ubuntu:linux:3.1"
	 * }
	 *
	 * {
	 *     "type" : "software",
	 *     "name" : "Linux 3.1",
	 *     "swid"  : "cpe-2.3:o:ubuntu:linux:3.1"
	 * }
	 */

	dep = json_object_new_object();
	CKNULL(dep, -ENOMEM);
	CKINT(json_object_object_add(dep, "type",
			json_object_new_string("software")));
	CKINT(json_object_object_add(dep, "name",
			json_object_new_string(def_oe->oe_env_name)));

	if (def_oe->cpe) {
		CKINT(json_object_object_add(dep, "cpe",
				json_object_new_string(def_oe->cpe)));
	} else if (def_oe->swid) {
		CKINT(json_object_object_add(dep, "swid",
				json_object_new_string(def_oe->swid)));
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY, "CPE or SWID missing\n");
		ret = -EINVAL;
		goto out;
	}

	if (def_oe->oe_description) {
		CKINT(json_object_object_add(dep, "description",
			json_object_new_string(def_oe->oe_description)));
	} else {
		CKINT(json_object_object_add(dep, "description",
				json_object_new_string("TOBEDEFINED")));
	}

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, dep, "Vendor JSON object");

	*json_oe = dep;

	return 0;

out:
	ACVP_JSON_PUT_NULL(dep);
	return ret;
}

static int acvp_oe_add_dep_url(uint32_t id, struct json_object *dep)
{
	int ret = -EINVAL;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_urlpath(NIST_VAL_OP_DEPENDENCY, url,
				  sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", id));
	CKINT(json_object_array_add(dep, json_object_new_string(url)));

out:
	return ret;
}

static int acvp_oe_build_oe(const struct def_oe *def_oe,
			    struct json_object **json_oe)
{

	struct json_object *oe = NULL, *dep = NULL;
	int ret = -EINVAL;

	/*
	 * {
	 *	"name": "Ubuntu Linux 3.1 on AMD 6272 Opteron Processor with Acme package installed",
	 *	"dependencyUrls": [
	 *		"/acvp/v1/dependencies/4",
	 *		"/acvp/v1/dependencies/5",
	 *		"/acvp/v1/dependencies/7"
	 *	]
	 *}
	 */
	if (def_oe->acvp_oe_dep_proc_id) {
		if (!dep) {
			dep = json_object_new_array();
			CKNULL(dep, -ENOMEM);
		}
		CKINT(acvp_oe_add_dep_url(def_oe->acvp_oe_dep_proc_id, dep));
	}
	if (def_oe->acvp_oe_dep_sw_id) {
		if (!dep) {
			dep = json_object_new_array();
			CKNULL(dep, -ENOMEM);
		}
		CKINT(acvp_oe_add_dep_url(def_oe->acvp_oe_dep_sw_id, dep));
	}

	oe = json_object_new_object();
	CKNULL(oe, -ENOMEM);
	CKINT(json_object_object_add(oe, "name",
			json_object_new_string(def_oe->oe_env_name)));
	if (dep) {
		CKINT(json_object_object_add(oe, "dependencyUrls", dep));
	} else {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No dependencies found for OE %s\n",
		       def_oe->oe_env_name);
	}

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, oe, "Vendor JSON object");

	*json_oe = oe;

	return 0;

out:
	ACVP_JSON_PUT_NULL(oe);
	ACVP_JSON_PUT_NULL(dep);
	return ret;
}

static int _acvp_str_match(const char *exp, const char *found, uint32_t id)
{
	if (strncmp(exp, found, strlen(exp))) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "OE mismatch for ID %u (expected: %s, found: %s)\n",
		       id, exp, found);
		return -ENOENT;
	}

	return 0;
}

static int acvp_oe_match_oe(struct def_oe *def_oe, struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(_acvp_str_match(def_oe->oe_env_name, str, def_oe->acvp_oe_id));

out:
	return ret;
}

static int acvp_oe_match_dep_sw(struct def_oe *def_oe,
			        struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(_acvp_str_match(def_oe->oe_env_name, str,
			      def_oe->acvp_oe_dep_sw_id));

	if (def_oe->cpe) {
		CKINT(json_get_string(json_oe, "cpe", &str));
		CKINT(_acvp_str_match(def_oe->cpe, str,
				      def_oe->acvp_oe_dep_sw_id));
	}

	if (def_oe->swid) {
		CKINT(json_get_string(json_oe, "swid", &str));
		CKINT(_acvp_str_match(def_oe->swid, str,
				      def_oe->acvp_oe_dep_sw_id));
	}

	CKINT(json_get_string(json_oe, "description", &str));
	CKINT(_acvp_str_match(def_oe->oe_description, str,
			      def_oe->acvp_oe_dep_sw_id));

	/* Last step as we got a successful match: get the ID */
	CKINT(json_get_string(json_oe, "url", &str));
	CKINT(acvp_get_trailing_number(str, &def_oe->acvp_oe_dep_sw_id));
	CKINT(acvp_def_update_oe_id(def_oe));

out:
	return ret;
}

static int acvp_oe_match_dep_proc(struct def_oe *def_oe,
			          struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "manufacturer", &str));
	CKINT(_acvp_str_match(def_oe->manufacturer, str,
			      def_oe->acvp_oe_dep_proc_id));

	CKINT(json_get_string(json_oe, "family", &str));
	CKINT(_acvp_str_match(def_oe->proc_family, str,
			      def_oe->acvp_oe_dep_proc_id));

	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(_acvp_str_match(def_oe->proc_name, str,
			      def_oe->acvp_oe_dep_proc_id));

	CKINT(json_get_string(json_oe, "series", &str));
	CKINT(_acvp_str_match(def_oe->proc_series, str,
			      def_oe->acvp_oe_dep_proc_id));

	/* Last step as we got a successful match: get the ID */
	CKINT(json_get_string(json_oe, "url", &str));
	CKINT(acvp_get_trailing_number(str, &def_oe->acvp_oe_dep_proc_id));
	CKINT(acvp_def_update_oe_id(def_oe));

out:
	return ret;
}

static int acvp_oe_match_dep(struct def_oe *def_oe,
			     struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "type", &str));
	if (!strncmp(str, "software", 8)) {
		CKINT(acvp_oe_match_dep_sw(def_oe, json_oe));
	} else if (!strncmp(str, "processor", 9)) {
		CKINT(acvp_oe_match_dep_proc(def_oe, json_oe));
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Dependency type %s unknown\n", str);
		ret = -ENOENT;
		goto out;
	}

out:
	return ret;
}

static int _acvp_oe_validate_one(const struct acvp_testid_ctx *testid_ctx,
				 struct def_oe *def_oe,
				 const char *url,
	int(*matcher)(struct def_oe *def_oe, struct json_object *json_oe))
{
	struct json_object *resp = NULL, *data = NULL;
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_oe_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));
	CKINT(matcher(def_oe, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* POST / PUT /oes */
static int acvp_oe_register_oe(const struct acvp_testid_ctx *testid_ctx,
			       struct def_oe *def_oe,
			       const char *url,
			       enum acvp_http_type type)
{
	struct json_object *json_oe = NULL;
	int ret;

	/* Build JSON object with the oe specification */
	CKINT(acvp_oe_build_oe(def_oe, &json_oe));

	CKINT(acvp_def_register(testid_ctx, json_oe, url,
				&def_oe->acvp_oe_id, type));

out:
	/* Write the newly obtained ID to the configuration file */
	acvp_def_update_oe_id(def_oe);

	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

/* GET /oes/<oeId> */
static int acvp_oe_validate_one_oe(const struct acvp_testid_ctx *testid_ctx,
				   struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	logger_status(LOGGER_C_ANY,
		      "Validating operational environment reference %u\n",
		      def_oe->acvp_oe_id);

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_oe->acvp_oe_id));

	ret = _acvp_oe_validate_one(testid_ctx, def_oe, url,
				    acvp_oe_match_oe);

	/* If we did not find a match, update the module definition */
	if (ret == -ENOENT) {
		if (ctx_opts->register_new_oe) {
			CKINT(acvp_oe_register_oe(testid_ctx, def_oe, url,
						   acvp_http_put));
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Definition for OE IDs %u different than found on ACVP server - you need to perform a (re)register operation\n",
			       def_oe->acvp_oe_id);
			goto out;
		}
	} else {
		ret |= acvp_def_update_oe_id(def_oe);
	}

out:
	return ret;
}

/* POST / PUT /dependencies */
static int acvp_oe_register_dep(const struct acvp_testid_ctx *testid_ctx,
				struct def_oe *def_oe,
				enum acvp_oe_dep_types type,
				enum acvp_http_type submit_type)
{
	struct json_object *json_oe = NULL;
	uint32_t *id;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	/* Build JSON object with the oe specification */
	switch (type) {
	case ACVP_OE_DEP_TYPE_PROC:
		CKINT(acvp_oe_build_dep_proc(def_oe, &json_oe));
		id = &def_oe->acvp_oe_dep_proc_id;
		break;
	case ACVP_OE_DEP_TYPE_SW:
		CKINT(acvp_oe_build_dep_sw(def_oe, &json_oe));
		id = &def_oe->acvp_oe_dep_sw_id;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE dependency type %u\n", type);
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_def_register(testid_ctx, json_oe, url, id, submit_type));

out:
	/* Write the newly obtained ID to the configuration file */
	acvp_def_update_oe_id(def_oe);

	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

/* GET /dependencies/<dependencyId> */
static int acvp_oe_validate_one_dep(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe,
				    enum acvp_oe_dep_types type,
				    uint32_t depid)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	logger_status(LOGGER_C_ANY,
		      "Validating operational environment dependency reference %u\n",
		      depid);

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", depid));

	ret = _acvp_oe_validate_one(testid_ctx, def_oe, url,
				    acvp_oe_match_dep);

	/* If we did not find a match, update the module definition */
	if (ret == -ENOENT) {
		if (ctx_opts->register_new_oe) {
			CKINT(acvp_oe_register_dep(testid_ctx, def_oe, type,
						   acvp_http_put));
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Definition for OE dependency IDs %u/%u different than found on ACVP server - you need to perform a (re)register operation\n",
			       def_oe->acvp_oe_dep_proc_id,
			       def_oe->acvp_oe_dep_sw_id);
			goto out;
		}
	} else {
logger(LOGGER_ERR, LOGGER_C_ANY, "REENABMLE!\n");
		//ret |= acvp_def_update_oe_id(def_oe);
		ret = acvp_def_update_oe_id(def_oe);
	}

out:
	return ret;
}

struct acvp_oe_match_struct {
	struct def_oe *def_oe;
	int(*matcher)(struct def_oe *def_oe, struct json_object *json_oe);
};

static int acvp_oe_match_cb(void *private, struct json_object *json_oe)
{
	struct acvp_oe_match_struct *matcher = private;
	int ret;

	ret = matcher->matcher(matcher->def_oe, json_oe);

	/* We found a match */
	if (!ret)
		return EINTR;
	/* We found no match, yet there was no error */
	if (ret == -ENOENT)
		return 0;

	/* We received an error */
	return ret;
}

static int _acvp_oe_validate_all(const struct acvp_testid_ctx *testid_ctx,
				 struct def_oe *def_oe,
				 const char *url,
	int(*matcher)(struct def_oe *def_oe, struct json_object *json_oe))
{
	struct acvp_oe_match_struct match_def;
	int ret;

	match_def.def_oe = def_oe;
	match_def.matcher = matcher;

	CKINT(acvp_paging_get(testid_ctx, url, &match_def,
			      &acvp_oe_match_cb));

out:
	return ret;
}

/* GET / POST /oes */
static int acvp_oe_validate_all_oe(const struct acvp_testid_ctx *testid_ctx,
				   struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	logger_status(LOGGER_C_ANY,
		      "Searching for operational environment reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));

	CKINT(_acvp_oe_validate_all(testid_ctx, def_oe, url, acvp_oe_match_oe));

	/* Our vendor data does not match any vendor on ACVP server */
	if (!ret) {
		if (ctx_opts->register_new_oe) {
			CKINT(acvp_oe_register_oe(testid_ctx, def_oe, url,
						  acvp_http_post));
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "No OE definition found - request registering this module\n");
			ret = -ENOENT;
			goto out;
		}
	} else if (ret == EINTR) {
		/* Write the newly obtained ID to the configuration file */
		CKINT(acvp_def_update_oe_id(def_oe));
	}

out:
	return ret;
}

static int acvp_oe_register_dep_type(const struct acvp_testid_ctx *testid_ctx,
				     struct def_oe *def_oe,
				     enum acvp_oe_dep_types type)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	int ret;

	if (ctx_opts->register_new_oe) {
		CKINT(acvp_oe_register_dep(testid_ctx, def_oe, type,
					     acvp_http_post));
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No dependencies definition found - request registering this module\n");
		ret = -ENOENT;
	}

out:
	return ret;
}

/* GET / POST /dependencies */
static int acvp_oe_validate_all_dep(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe)
{
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	logger_status(LOGGER_C_ANY,
		      "Searching for operational environment reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));

	CKINT(_acvp_oe_validate_all(testid_ctx, def_oe, url,
				    acvp_oe_match_dep));

	/* Our vendor data does not match any vendor on ACVP server */
	if (!ret) {
		if (!def_oe->acvp_oe_dep_proc_id) {
			ret = acvp_oe_register_dep_type(testid_ctx, def_oe,
							ACVP_OE_DEP_TYPE_PROC);
		}
		if (!def_oe->acvp_oe_dep_sw_id) {
			ret |= acvp_oe_register_dep_type(testid_ctx, def_oe,
							 ACVP_OE_DEP_TYPE_SW);
		}
		if (ret)
			goto out;
	} else if (ret == EINTR) {
		/* Write the newly obtained ID to the configuration file */
		CKINT(acvp_def_update_oe_id(def_oe));
	}

out:
	return ret;
}

int acvp_oe_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct definition *def;
	struct def_oe *def_oe;
	struct json_object *json_oe = NULL;
	int ret = 0, ret2;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Vendor handling: cipher definitions missing\n");
	def_oe = def->oe;
	CKNULL_LOG(def_oe, -EINVAL,
		   "Vendor handling: oe definitions missing\n");
	CKNULL_LOG(ctx, -EINVAL, "Vendor validation: ACVP context missing\n");
	req_details = &ctx->req_details;

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url,
				      sizeof(url)));
		acvp_oe_register_dep(testid_ctx, def_oe, ACVP_OE_DEP_TYPE_PROC,
				     acvp_http_post);
		acvp_oe_register_dep(testid_ctx, def_oe, ACVP_OE_DEP_TYPE_SW,
				     acvp_http_post);
		acvp_oe_register_oe(testid_ctx, def_oe, url, acvp_http_post);
		goto out;
	}

	/* Check if we have an outstanding request */
	ret2 = acvp_def_obtain_request_result(testid_ctx,
					      &def_oe->acvp_oe_dep_proc_id);
	ret2 |= acvp_def_obtain_request_result(testid_ctx,
					       &def_oe->acvp_oe_dep_sw_id);
	ret2 |= acvp_def_obtain_request_result(testid_ctx,
					       &def_oe->acvp_oe_id);
	/* Write the newly obtained ID to the configuration file */
	CKINT(acvp_def_update_oe_id(def_oe));
	if (ret2) {
		ret = ret2;
		goto out;
	}

	if (def_oe->acvp_oe_dep_proc_id) {
		CKINT(acvp_oe_validate_one_dep(testid_ctx, def_oe,
					       ACVP_OE_DEP_TYPE_PROC,
					       def_oe->acvp_oe_dep_proc_id));
	}

	if (def_oe->acvp_oe_dep_sw_id) {
		CKINT(acvp_oe_validate_one_dep(testid_ctx, def_oe,
					       ACVP_OE_DEP_TYPE_SW,
					       def_oe->acvp_oe_dep_sw_id));
	}

	if (!def_oe->acvp_oe_dep_proc_id || !def_oe->acvp_oe_dep_sw_id) {
		CKINT(acvp_oe_validate_all_dep(testid_ctx, def_oe));
	}

	if (def_oe->acvp_oe_id) {
		CKINT(acvp_oe_validate_one_oe(testid_ctx, def_oe));
	} else {
		CKINT(acvp_oe_validate_all_oe(testid_ctx, def_oe));
	}

out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}
