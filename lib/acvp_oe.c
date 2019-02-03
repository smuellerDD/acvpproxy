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
	 */

	dep = json_object_new_object();
	CKNULL(dep, -ENOMEM);
	CKINT(json_object_object_add(dep, "type",
			json_object_new_string("software")));
	CKINT(json_object_object_add(dep, "name",
			json_object_new_string(def_oe->oe_env_name)));
	CKINT(json_object_object_add(dep, "cpe",
			json_object_new_string(def_oe->cpe)));

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
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "OE mismatch for ID %u (expected: %s, found: %s)\n",
		       id, exp, found);
		return -ENOENT;
	}

	return 0;
}

static int acvp_oe_match_oe(const struct def_oe *def_oe,
			    struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(_acvp_str_match(def_oe->oe_env_name, str, def_oe->acvp_oe_id));

out:
	return ret;
}

static int acvp_oe_match_dep_sw(const struct def_oe *def_oe,
			        struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(_acvp_str_match(def_oe->oe_env_name, str, def_oe->acvp_oe_id));

	CKINT(json_get_string(json_oe, "cpe", &str));
	CKINT(_acvp_str_match(def_oe->cpe, str, def_oe->acvp_oe_dep_sw_id));

out:
	return ret;
}

static int acvp_oe_match_dep_proc(const struct def_oe *def_oe,
			          struct json_object *json_oe)
{
	int ret;
	const char *str;

	CKINT(json_get_string(json_oe, "manufactuer", &str));
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

out:
	return ret;
}

static int acvp_oe_match_dep(const struct def_oe *def_oe,
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
		/* No error - fall through */
		goto out;
	}

out:
	return ret;
}

static int _acvp_oe_validate_one(const struct acvp_testid_ctx *testid_ctx,
				 const struct def_oe *def_oe,
				 const char *url,
	int(*checker)(const struct def_oe *def_oe, struct json_object *json_oe))
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
	CKINT(checker(def_oe, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* GET /oes/<oeId> */
static int acvp_oe_validate_one_oe(const struct acvp_testid_ctx *testid_ctx,
				   const struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_oe->acvp_oe_id));

	CKINT(_acvp_oe_validate_one(testid_ctx, def_oe, url,
				    acvp_oe_match_oe));

out:
	return ret;
}

/* GET /dependencies/<dependencyId> */
static int acvp_oe_validate_one_dep(const struct acvp_testid_ctx *testid_ctx,
				    const struct def_oe *def_oe,
				    uint32_t depid)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", depid));

	CKINT(_acvp_oe_validate_one(testid_ctx, def_oe, url,
				    acvp_oe_match_dep));

out:
	return ret;
}

int acvp_def_register(const struct acvp_testid_ctx *testid_ctx,
		      struct json_object *json,
		      const char *url, uint32_t *id)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	const struct acvp_net_ctx *net;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct json_object *resp = NULL, *data = NULL, *json_submission = NULL;
	struct acvp_na_ex netinfo;
	ACVP_BUFFER_INIT(submit);
	ACVP_BUFFER_INIT(response);
	ACVP_BUFFER_INIT(tmpbuf);
	int ret, ret2;
	const char *json_request, *uri;

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "Registering new object\n");

	/* Build the JSON object to be submitted */
	json_submission = json_object_new_array();
	CKNULL(json_submission, -ENOMEM);

	/* Array entry for version */
	CKINT(acvp_req_add_version(json_submission));

	/* Add oe to submission JSON object */
	json_object_get(json);
	CKINT(json_object_array_add(json_submission, json));

	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(json_submission,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}


	tmpbuf.buf = (uint8_t *)json_object_to_json_string_ext(json_submission,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	tmpbuf.len = strlen((char *)tmpbuf.buf);
	CKINT(ds->acvp_datastore_write_testid(testid_ctx,
					      "operational_environment.json",
					      false, &tmpbuf));

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(json_submission,
					JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	submit.buf = (uint8_t *)json_request;
	submit.len = strlen(json_request);

	/* Refresh the ACVP JWT token by re-logging in. */
	CKINT(acvp_login(testid_ctx));

	CKINT(acvp_get_net(&net));
	netinfo.net = net;
	netinfo.url = url;
	mutex_reader_lock(&auth->mutex);
	ret2 = na->acvp_http_post(&netinfo, &submit, &response);
	mutex_reader_unlock(&auth->mutex);

	if (!response.buf || !response.len)
		goto out;

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response.buf);

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response.buf, &resp, &data));
	CKINT(json_get_string(data, "url", &uri));

	/* Get the oe ID which is the last pathname component */
	CKINT(acvp_get_trailing_number(uri, id));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_submission);
	acvp_free_buf(&response);
	return ret;
}

/* POST /oes */
static int acvp_oe_register_oe(const struct acvp_testid_ctx *testid_ctx,
			       struct def_oe *def_oe)
{
	struct json_object *json_oe = NULL;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));

	/* Build JSON object with the oe specification */
	CKINT(acvp_oe_build_oe(def_oe, &json_oe));

	CKINT(acvp_def_register(testid_ctx, json_oe, url,
				&def_oe->acvp_oe_id));

	/* Write the newly obtained ID to the configuration file */
	CKINT(acvp_def_update_oe_id(def_oe));

out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

/* POST /dependencies */
static int acvp_oe_register_dep(const struct acvp_testid_ctx *testid_ctx,
				struct def_oe *def_oe,
				enum acvp_oe_dep_types type, uint32_t *id)
{
	struct json_object *json_oe = NULL;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	/* Build JSON object with the oe specification */
	switch (type) {
	case ACVP_OE_DEP_TYPE_PROC:
		CKINT(acvp_oe_build_dep_proc(def_oe, &json_oe));
		break;
	case ACVP_OE_DEP_TYPE_SW:
		CKINT(acvp_oe_build_dep_sw(def_oe, &json_oe));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE dependency type %u\n", type);
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_def_register(testid_ctx, json_oe, url, id));

	/* Write the newly obtained ID to the configuration file */
	CKINT(acvp_def_update_oe_id(def_oe));

out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

static int _acvp_oe_validate_all(const struct acvp_testid_ctx *testid_ctx,
				 struct def_oe *def_oe,
				 const char *url,
				 const char *searchkeyword,
	int(*checker)(const struct def_oe *def_oe, struct json_object *json_oe),
	int (*debug_logger)(const struct acvp_testid_ctx *testid_ctx,
			    const struct acvp_buf *buf, int err))
{
	struct json_object *resp = NULL, *data = NULL, *array;
	ACVP_BUFFER_INIT(buf);
	unsigned int i;
	int ret, ret2;
	bool found = false;

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(debug_logger(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(buf.buf, &resp, &data));

	CKINT(json_find_key(data, searchkeyword, &array, json_type_array));
	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *oe = json_object_array_get_idx(array, i);

		if (!checker(def_oe, oe)) {
			found = true;
			break;
		}
	}

	if (!found)
		ret = -ENOENT;

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* GET /oes */
static int acvp_oe_validate_all_oe(const struct acvp_testid_ctx *testid_ctx,
				   struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	ctx_opts = &ctx->options;

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));

	ret = _acvp_oe_validate_all(testid_ctx, def_oe, url, "oes",
				    acvp_oe_match_oe, acvp_store_oe_debug);

	/* No matching entry found - create one */
	if ((ret == -ENOENT) && ctx_opts->register_new_oe) {
		CKINT(acvp_oe_register_oe(testid_ctx, def_oe));
	}

out:
	return ret;
}

/* GET /dependencies */
static int acvp_oe_validate_all_dep(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe,
				    enum acvp_oe_dep_types type,
				    uint32_t *id)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	ctx_opts = &ctx->options;

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));

	ret = _acvp_oe_validate_all(testid_ctx, def_oe, url, "dependencies",
				    acvp_oe_match_dep, acvp_store_oe_debug);

	/* No matching entry found - create one */
	if ((ret == -ENOENT) && ctx_opts->register_new_oe) {
		CKINT(acvp_oe_register_dep(testid_ctx, def_oe, type, id));
	}

out:
	return ret;
}

int acvp_oe_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct acvp_opts_ctx *ctx_opts;
	const struct definition *def;
	struct def_oe *def_oe;
	struct json_object *json_oe = NULL;
	int ret = 0;

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
	ctx_opts = &ctx->options;

	if (req_details->dump_register) {
		acvp_oe_register_dep(testid_ctx, def_oe, ACVP_OE_DEP_TYPE_PROC,
				     &def_oe->acvp_oe_dep_proc_id);
		acvp_oe_register_dep(testid_ctx, def_oe, ACVP_OE_DEP_TYPE_SW,
				     &def_oe->acvp_oe_dep_sw_id);
		acvp_oe_register_oe(testid_ctx, def_oe);
		goto out;
	}

	if (def_oe->acvp_oe_dep_proc_id) {
		if (ctx_opts->register_new_oe) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Cannot register OE processor definition which has already a oe ID (id %d)\n",
			       def_oe->acvp_oe_dep_proc_id);
			return -EINVAL;
		}
		CKINT(acvp_oe_validate_one_dep(testid_ctx, def_oe,
					       def_oe->acvp_oe_dep_proc_id));
	} else {
		CKINT(acvp_oe_validate_all_dep(testid_ctx, def_oe,
					       ACVP_OE_DEP_TYPE_PROC,
					       &def_oe->acvp_oe_dep_proc_id));
	}

	if (def_oe->acvp_oe_dep_sw_id) {
		if (ctx_opts->register_new_oe) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Cannot register OE software definition which has already a oe ID (id %d)\n",
			       def_oe->acvp_oe_dep_sw_id);
			return -EINVAL;
		}
		CKINT(acvp_oe_validate_one_dep(testid_ctx, def_oe,
					       def_oe->acvp_oe_dep_sw_id));
	} else {
		CKINT(acvp_oe_validate_all_dep(testid_ctx, def_oe,
					       ACVP_OE_DEP_TYPE_SW,
					       &def_oe->acvp_oe_dep_sw_id));
	}

	if (def_oe->acvp_oe_id) {
		if (ctx_opts->register_new_oe) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Cannot register oe definition which has already a oe ID (id %d)\n",
			       def_oe->acvp_oe_id);
			return -EINVAL;
		}
		CKINT(acvp_oe_validate_one_oe(testid_ctx, def_oe));
	} else {
		CKINT(acvp_oe_validate_all_oe(testid_ctx, def_oe));
	}

out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}
