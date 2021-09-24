/* ACVP proxy protocol handler for managing the operational env information
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

/*****************************************************************************
 * Builder
 *****************************************************************************/
static int acvp_oe_proc_name(const struct def_dependency *def_dep, char *tmp,
			     size_t tmplen)
{
	snprintf(tmp, tmplen, "Processor %s (processor family %s) from %s",
		 def_dep->proc_name, def_dep->proc_family,
		 def_dep->manufacturer);
	return 0;
}

static int acvp_oe_build_dep_proc(const struct def_dependency *def_dep,
				  struct json_object **json_oe,
				  bool check_ignore_flag)
{
	struct json_object *dep = NULL;
	const char *typename;
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

	CKINT(acvp_dep_type2name(def_dep->def_dependency_type, &typename));

	dep = json_object_new_object();
	CKNULL(dep, -ENOMEM);

	//TODO: SPEC says it is called "cpu", but this works as well!?
	if (!check_ignore_flag) {
		CKINT(json_object_object_add(dep, "type",
					     json_object_new_string(typename)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_dep->manufacturer_i)) {
		CKINT(json_object_object_add(
			dep, "manufacturer",
			json_object_new_string(def_dep->manufacturer)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_dep->proc_family_i)) {
		CKINT(json_object_object_add(
			dep, "family",
			json_object_new_string(def_dep->proc_family)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_dep->proc_name_i)) {
		CKINT(json_object_object_add(
			dep, "name",
			json_object_new_string(def_dep->proc_name)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_dep->proc_series_i)) {
		CKINT(json_object_object_add(
			dep, "series",
			json_object_new_string(def_dep->proc_series)));
	}

	if (acvp_check_ignore(check_ignore_flag, def_dep->description_i)) {
		char tmp[1024];

		CKINT(acvp_oe_proc_name(def_dep, tmp, sizeof(tmp)));
		CKINT(json_object_object_add(dep, "description",
					     json_object_new_string(tmp)));
	}

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

static int acvp_oe_build_dep_sw(const struct def_dependency *def_dep,
				struct json_object **json_oe,
				bool check_ignore_flag)
{
	struct json_object *dep = NULL;
	const char *typename;
	int ret = -EINVAL;

	/* We are required to have an entry at this point. */
	if (!def_dep->name) {
		*json_oe = NULL;
		return 0;
	}

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

	CKINT(acvp_dep_type2name(def_dep->def_dependency_type, &typename));

	dep = json_object_new_object();
	CKNULL(dep, -ENOMEM);

	if (!check_ignore_flag) {
		CKINT(json_object_object_add(dep, "type",
					     json_object_new_string(typename)));
	}
	if (acvp_check_ignore(check_ignore_flag, def_dep->name_i)) {
		CKINT(json_object_object_add(dep, "name",
					json_object_new_string(def_dep->name)));
	}

	if (def_dep->cpe) {
		if (acvp_check_ignore(check_ignore_flag, def_dep->cpe_i)) {
			CKINT(json_object_object_add(
				dep, "cpe",
				json_object_new_string(def_dep->cpe)));
			CKINT(json_object_object_add(dep, "swid", NULL));
		}
	} else if (def_dep->swid) {
		if (acvp_check_ignore(check_ignore_flag, def_dep->swid_i)) {
			CKINT(json_object_object_add(dep, "cpe", NULL));
			CKINT(json_object_object_add(
				dep, "swid",
				json_object_new_string(def_dep->swid)));
		}
	} else {
		if (acvp_check_ignore(check_ignore_flag, def_dep->cpe_i)) {
			CKINT(json_object_object_add(dep, "cpe", NULL));
		}
		if (acvp_check_ignore(check_ignore_flag, def_dep->swid_i)) {
			CKINT(json_object_object_add(dep, "swid", NULL));
		}
		logger(LOGGER_VERBOSE, LOGGER_C_ANY, "No CPE or SWID found\n");
	}

	if (acvp_check_ignore(check_ignore_flag, def_dep->cpe_i)) {
		if (def_dep->description) {
			CKINT(json_object_object_add(
				dep, "description",
				json_object_new_string(def_dep->description)));
		} else {
			CKINT(json_object_object_add(
				dep, "description",
				json_object_new_string(def_dep->name)));
		}
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

	CKINT(acvp_create_urlpath(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", id));
	CKINT(json_object_array_add(dep, json_object_new_string(url)));

out:
	return ret;
}

/*****************************************************************************
 * Matcher
 *****************************************************************************/
static int acvp_str_match_zero(const char *exp, const char *found,
			       const uint32_t id)
{
	size_t exp_len = 0, found_len = 0;

	if (exp)
		exp_len = strlen(exp);
	if (found)
		found_len = strlen(found);

	/*
	 * We need that check because we want to consider a NULL and a
	 * zero-length data to match. But if there is a NULL on one side and
	 * a filled buffer on the other, we should not match.
	 */
	if (exp_len != found_len)
		return -ENOENT;

	return acvp_str_match(exp, found, id);
}

static int acvp_oe_match_dep_sw(struct def_dependency *def_dep,
				struct json_object *json_oe)
{
	int ret, ret2;
	const char *str;

	if (!def_dep->name)
		return 0;

	/*
	 * no error check on remote data read -> if not existent, its string
	 * is NULL
	 */
	/* commented-out checks are "not explicit" attributes */
	json_get_string(json_oe, "name", &str);
	ret = acvp_str_match_zero(def_dep->name, str, def_dep->acvp_dep_id);
	def_dep->name_i = !ret;
	ret2 = ret;

	if (def_dep->cpe) {
		json_get_string(json_oe, "cpe", &str);
		ret = acvp_str_match_zero(def_dep->cpe, str,
					  def_dep->acvp_dep_id);
		//def_dep->cpe_i = !ret;
		ret2 |= ret;
	}

	if (def_dep->swid) {
		json_get_string(json_oe, "swid", &str);
		ret = acvp_str_match_zero(def_dep->swid, str,
					  def_dep->acvp_dep_id);
		//def_dep->swid_i = !ret;
		ret2 |= ret;
	}

	/*
	 * Check for the presence of a SWID/CPE on the server where locally
	 * there is none defined.
	 */
	if (!def_dep->swid && !def_dep->cpe) {
		ret = json_get_string(json_oe, "swid", &str);

		/* Found one, we have a mismatch */
		if (!ret)
			ret2 |= -ENOENT;
		//else
		//	def_dep->swid_i = true;

		ret = json_get_string(json_oe, "cpe", &str);

		/* Found one, we have a mismatch */
		if (!ret)
			ret2 |= -ENOENT;
		//else
		//	def_dep->cpe_i = true;
	}

	json_get_string(json_oe, "description", &str);

	if (def_dep->description) {
		ret = acvp_str_match_zero(def_dep->description, str,
					  def_dep->acvp_dep_id);
	} else {
		ret = acvp_str_match_zero(def_dep->name, str,
					  def_dep->acvp_dep_id);
	}
	def_dep->description_i = !ret;
	ret2 |= ret;

	if (!ret2) {
		/* Last step as we got a successful match: get the ID */
		CKINT(json_get_string(json_oe, "url", &str));
		CKINT(acvp_get_id_from_url(str, &def_dep->acvp_dep_id));
	}

	ret = ret2;

out:
	return ret;
}

static int acvp_oe_match_dep_proc(struct def_dependency *def_dep,
				  struct json_object *json_oe)
{
	char tmp[1024];
	int ret, ret2;
	const char *str;

	/*
	 * no error check on remote data read -> if not existent, its string
	 * is NULL
	 */

	/* commented-out checks are "not explicit" attributes */
	json_get_string(json_oe, "manufacturer", &str);
	ret = acvp_str_match_zero(def_dep->manufacturer, str,
				  def_dep->acvp_dep_id);
	//def_dep->manufacturer_i = !ret;
	ret2 = ret;

	json_get_string(json_oe, "family", &str);
	ret = acvp_str_match_zero(def_dep->proc_family, str,
				  def_dep->acvp_dep_id);
	//def_dep->proc_family_i = !ret;
	ret2 |= ret;

	json_get_string(json_oe, "name", &str);
	ret = acvp_str_match_zero(def_dep->proc_name, str,
				  def_dep->acvp_dep_id);
	def_dep->proc_name_i = !ret;
	ret2 |= ret;

	json_get_string(json_oe, "series", &str);
	ret = acvp_str_match_zero(def_dep->proc_series, str,
				  def_dep->acvp_dep_id);
	//def_dep->proc_series_i = !ret;
	ret2 |= ret;

	CKINT(acvp_oe_proc_name(def_dep, tmp, sizeof(tmp)));
	json_get_string(json_oe, "description", &str);
	ret = acvp_str_match_zero(tmp, str, def_dep->acvp_dep_id);
	def_dep->description_i = !ret;
	ret2 |= ret;

	if (!ret2) {
		/* Last step as we got a successful match: get the ID */
		json_get_string(json_oe, "url", &str);
		CKINT(acvp_get_id_from_url(str, &def_dep->acvp_dep_id));
	}

	ret = ret2;

out:
	return ret;
}

static int acvp_oe_match_dep(const struct acvp_testid_ctx *testid_ctx,
			     struct def_oe *def_oe,
			     struct def_dependency *def_dep,
			     struct json_object *json_oe)
{
	enum def_dependency_type type;
	int ret;
	const char *str;

	(void)testid_ctx;
	(void)def_oe;

	CKINT(json_get_string(json_oe, "type", &str));
	CKINT(acvp_dep_name2type(str, &type));
	switch (type) {
	case def_dependency_firmware:
	case def_dependency_os:
	case def_dependency_software:
		CKINT(acvp_oe_match_dep_sw(def_dep, json_oe));
		break;
	case def_dependency_hardware:
		CKINT(acvp_oe_match_dep_proc(def_dep, json_oe));
		break;
	default:
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Dependency type %s unknown\n", str);
		ret = -ENOENT;
		goto out;
	}

out:
	return ret;
}

/*****************************************************************************
 * Dependency handler
 *****************************************************************************/
static int _acvp_oe_validate_one(
	const struct acvp_testid_ctx *testid_ctx, struct def_oe *def_oe,
	struct def_dependency *def_dep, const char *url,
	struct json_object **resp, struct json_object **data,
	int (*matcher)(const struct acvp_testid_ctx *testid_ctx,
		       struct def_oe *def_oe, struct def_dependency *def_dep,
		       struct json_object *json_oe))
{
	ACVP_BUFFER_INIT(buf);
	int ret, ret2;

	ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);

	CKINT(acvp_store_oe_debug(testid_ctx, &buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the verdict data. */
	CKINT(acvp_req_strip_version(&buf, resp, data));
	CKINT(matcher(testid_ctx, def_oe, def_dep, *data));

out:
	acvp_free_buf(&buf);
	return ret;
}

static int acvp_oe_register_dep_build(struct def_dependency *def_dep,
				      struct json_object **json_dep,
				      uint32_t **id, bool check_ignore_flag)
{
	struct json_object *dep = NULL;
	int ret = 0;

	switch (def_dep->def_dependency_type) {
	case def_dependency_hardware:
		CKINT(acvp_oe_build_dep_proc(def_dep, &dep, check_ignore_flag));
		*id = &def_dep->acvp_dep_id;
		break;
	case def_dependency_firmware:
	case def_dependency_os:
	case def_dependency_software:
		CKINT(acvp_oe_build_dep_sw(def_dep, &dep, check_ignore_flag));
		*id = &def_dep->acvp_dep_id;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE dependency type %u\n",
		       def_dep->def_dependency_type);
		ret = -EINVAL;
		goto out;
		break;
	}

	*json_dep = dep;

out:
	return ret;
}

/* POST / PUT / DELETE /dependencies */
static int acvp_oe_register_dep(const struct acvp_testid_ctx *testid_ctx,
				struct def_dependency *def_dep,
				enum acvp_http_type submit_type,
				const bool asked)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_dep = NULL;
	uint32_t *id;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_oe_register_dep_build(def_dep, &json_dep, &id, asked));

	if (!json_dep)
		goto out;

	if (!req_details->dump_register && !ctx_opts->register_new_oe &&
	    !asked) {
		logger_status(LOGGER_C_ANY, "Data to be registered: %s\n",
			      json_object_to_json_string_ext(
				      json_dep,
				      JSON_C_TO_STRING_PRETTY |
					      JSON_C_TO_STRING_NOSLASHESCAPE));
		if (ask_yes("No module definition found - shall the dependency for an OE be registered")) {
			ret = -ENOENT;
			goto out;
		}
	}

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_meta_register(testid_ctx, json_dep, url, sizeof(url), id,
				 submit_type));

out:
	ACVP_JSON_PUT_NULL(json_dep);
	return ret;
}

/* GET /dependencies/<dependencyId> */
static int _acvp_oe_validate_one_dep(const struct acvp_testid_ctx *testid_ctx,
				     struct def_oe *def_oe,
				     struct def_dependency *def_dep,
				     struct json_object **resp,
				     struct json_object **data)
{
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	logger_status(
		LOGGER_C_ANY,
		"Validating operational environment dependency reference %u\n",
		def_dep->acvp_dep_id);

	CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_dep->acvp_dep_id));

	CKINT(_acvp_oe_validate_one(testid_ctx, def_oe, def_dep, url, resp,
				    data, acvp_oe_match_dep));

out:
	return ret;
}

static int acvp_oe_validate_one_dep(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe,
				    struct def_dependency *def_dep)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *json_dep = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;
	unsigned int http_type = 0;
	bool asked = false;

	if (!def_dep->acvp_dep_id)
		return 0;

	ret = _acvp_oe_validate_one_dep(testid_ctx, def_oe, def_dep, &resp,
					&found_data);
	if (!ret)
		return 0;

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_OE, ctx_opts,
				       def_dep->acvp_dep_id, &http_type);
	if (ret == -ENOENT) {
		uint32_t *id;

		CKINT(acvp_oe_register_dep_build(def_dep, &json_dep, &id,
						 !!found_data));
		if (json_dep) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_dep,
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
		       "Conversion from search type to HTTP request type failed for OE dependencies\n");
		goto out;
	} else if (http_type == acvp_http_put) {
		uint32_t *id;

		/* Update requested */
		CKINT(acvp_oe_register_dep_build(def_dep, &json_dep, &id, true));
		if (json_dep) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_dep,
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

	CKINT(acvp_oe_register_dep(testid_ctx, def_dep, http_type, asked));

	if (http_type == acvp_http_put)
		logger_status(
			LOGGER_C_ANY,
			"OE dependency for updated - repeat the operation for the operational environment after the processor update was approved to update the name of the OE on the certificate which is automatically created based on the processor information\n");

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_dep);
	return ret;
}

struct acvp_oe_match_struct {
	const struct acvp_testid_ctx *testid_ctx;
	struct def_oe *def_oe;
	struct def_dependency *def_dep;
	int (*matcher)(const struct acvp_testid_ctx *testid_ctx,
		       struct def_oe *def_oe, struct def_dependency *def_dep,
		       struct json_object *json_oe);
};

/**
 * NIST requests the "name" keyword in the OE JSON definition to be unique with
 * a human readable information about the OS and the processor information.
 *
 * We are assembling such a string here but making sure our JSON information
 * does not keep duplicate information.
 */
static int acvp_oe_generate_oe_string(const struct def_oe *def_oe, char *str,
				      const size_t stringlen)
{
	struct def_dependency *def_dep;
	int ret = 0;
	bool first_in = false;

	str[0] = '\0';

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (first_in)
			CKINT(acvp_extend_string(str, stringlen, " on "));

		if (def_dep->name) {
			CKINT(acvp_extend_string(str, stringlen, "%s",
						 def_dep->name));
			first_in = true;
		}

		if (def_dep->manufacturer) {
			CKINT(acvp_extend_string(str, stringlen, "%s",
						 def_dep->manufacturer));
			first_in = true;
		}

		if (def_dep->proc_series) {
			CKINT(acvp_extend_string(str, stringlen, " %s",
						 def_dep->proc_series));

			if (def_dep->proc_name &&
			    strncmp(def_dep->proc_series, def_dep->proc_name,
				    strlen(def_dep->proc_name))) {
				CKINT(acvp_extend_string(str, stringlen, " %s",
							 def_dep->proc_name));
			}
		} else {
			if (def_dep->proc_name)
				CKINT(acvp_extend_string(str, stringlen, " %s",
							 def_dep->proc_name));
		}
	}

out:
	return ret;
}

static int acvp_oe_match_oe_deps_matcher(struct json_object *dep,
					 struct def_oe *def_oe)
{
	struct def_dependency *def_dep;
	enum def_dependency_type type;
	int ret;
	const char *str;

	CKINT(json_get_string(dep, "type", &str));

	CKINT(acvp_dep_name2type(str, &type));

	/*
	 * Software is only matched if we have an oeEnvName as
	 * this reference specifies the underlying software.
	 */
	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->def_dependency_type != type)
			continue;

		switch (type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			ret = acvp_oe_match_dep_sw(def_dep, dep);
			if (!ret)
				goto out;
			else if (ret != -ENOENT)
				goto out;
			break;
		case def_dependency_hardware:
			ret = acvp_oe_match_dep_proc(def_dep, dep);
			if (!ret)
				goto out;
			else if (ret != -ENOENT)
				goto out;
			break;
		default:
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "Dependency type %s unknown\n", str);
			ret = -ENOENT;
			goto out;
		}
	}

out:
	return ret;
}

/* Process an array of dependency URLs */
#if 0
/* check with ACVP server */
static int acvp_oe_match_oe_depurls(const struct acvp_testid_ctx *testid_ctx,
				    const struct def_oe *def_oe,
				    struct json_object *json_oe)
{
	struct json_object *tmp, *resp = NULL, *data;
	ACVP_BUFFER_INIT(buf);
	unsigned int i;
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	ret = json_find_key(json_oe, "dependencyUrls", &tmp, json_type_array);
	/* We only check the dependencyUrls if they are present */
	if (ret)
		return 0;

	for (i = 0; i < json_object_array_length(tmp); i++) {
		uint32_t id = 0;
		struct json_object *dep =
				json_object_array_get_idx(tmp, i);

		/* Get the dependency ID */
		CKINT(json_object_is_type(dep, json_type_string));
		CKINT(acvp_get_trailing_number(json_object_get_string(dep),
					       &id));

		/* Download the dependency */
		CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, sizeof(url)));
		CKINT(acvp_extend_string(url, sizeof(url), "/%u", id));

		ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);
		CKINT(acvp_store_oe_debug(testid_ctx, &buf, ret2));
		if (ret2) {
			ret = ret2;
			goto out;
		}

		/* Strip the version array entry and get the verdict data. */
		CKINT(acvp_req_strip_version(&buf, &resp, &data));

		/* Analyze the dependency */
		CKINT(acvp_oe_match_oe_deps_matcher(data, def_oe));

		ACVP_JSON_PUT_NULL(resp);
		acvp_free_buf(&buf);
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* Process an array of fully exploded dependencies */
static int acvp_oe_match_oe_deps(struct def_oe *def_oe,
				 struct json_object *json_oe)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;

	ret = json_find_key(json_oe, "dependencies", &tmp, json_type_array);
	/* We only check the dependencies if they are present */
	if (ret)
		return 0;

	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *dep =
				json_object_array_get_idx(tmp, i);

		CKINT(acvp_oe_match_oe_deps_matcher(dep, def_oe));
	}

out:
	return ret;
}

#else
/* check with local DB server */
static int acvp_oe_match_oe_depurls(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe,
				    struct json_object *json_oe)
{
	struct def_dependency *def_dep;
	struct json_object *tmp, *resp = NULL, *data;
	ACVP_BUFFER_INIT(buf);
	unsigned int i = 0;
	int ret;

	(void)testid_ctx;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if ((def_dep->def_dependency_type == def_dependency_software) &&
		    !def_dep->name)
			continue;
		i++;
	}

	ret = json_find_key(json_oe, "dependencyUrls", &tmp, json_type_array);
	/* We only check the dependencyUrls if they are present */
	if (ret)
		return 0;

	if (i != json_object_array_length(tmp))
		return -EAGAIN;

	/* Ensure that all IDs given by the server are found locally */
	for (i = 0; i < json_object_array_length(tmp); i++) {
		uint32_t id = 0;
		bool found = false;
		struct json_object *dep = json_object_array_get_idx(tmp, i);

		/* Get the dependency ID */
		CKINT(json_object_is_type(dep, json_type_string));
		CKINT(acvp_get_trailing_number(json_object_get_string(dep),
					       &id));

		for (def_dep = def_oe->def_dep; def_dep;
		     def_dep = def_dep->next) {
			if (id == def_dep->acvp_dep_id) {
				found = true;
				break;
			}
		}

		if (!found) {
			/*
			 * If the ID is not found (e.g. we do not have an ID
			 * locally), perform a full match of the dependencies
			 * pointed to by dependenciesUrls.
			 */
			char url[ACVP_NET_URL_MAXLEN];
			int ret2;

			/* Download the dependency */
			CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url,
					      sizeof(url)));
			CKINT(acvp_extend_string(url, sizeof(url), "/%u", id));

			ret2 = acvp_process_retry_testid(testid_ctx, &buf, url);
			CKINT(acvp_store_oe_debug(testid_ctx, &buf, ret2));
			if (ret2) {
				ret = ret2;
				goto out;
			}

			/*
			 * Strip the version array entry and get the verdict
			 * data.
			 */
			CKINT(acvp_req_strip_version(&buf, &resp, &data));

			/* Analyze the dependency */
			CKINT(acvp_oe_match_oe_deps_matcher(data, def_oe));

			ACVP_JSON_PUT_NULL(resp);
			acvp_free_buf(&buf);
		} else {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "Dependency ID %u provided by ACVP server for OE %u found also in local database\n",
			       def_dep->acvp_dep_id, def_oe->acvp_oe_id);
		}
	}

	/* Ensure that all local IDs are found on the server */
	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		bool found = false;

		/*
		 * If we have no local dependency ID set (e.g. when using the
		 * old dependency definition config file structure and having
		 * no software), then we trivially match.
		 */
		if (!def_dep->acvp_dep_id)
			continue;

		for (i = 0; i < json_object_array_length(tmp); i++) {
			uint32_t id = 0;
			struct json_object *dep =
				json_object_array_get_idx(tmp, i);

			/* Get the dependency ID */
			CKINT(json_object_is_type(dep, json_type_string));
			CKINT(acvp_get_trailing_number(
				json_object_get_string(dep), &id));

			if (id == def_dep->acvp_dep_id) {
				found = true;
				break;
			}
		}

		if (!found) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Dependency ID %u found on local database without a match on server\n",
			       def_dep->acvp_dep_id);
			def_dep->acvp_dep_id = 0;
			ret = -EAGAIN;
			goto out;
		}

		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Dependency ID %u found on local database for OE %u found also in ACVP server database\n",
		       def_dep->acvp_dep_id, def_oe->acvp_oe_id);
	}

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}

/* Process an array of fully exploded dependencies */
static int acvp_oe_match_oe_deps(struct def_oe *def_oe,
				 struct json_object *json_oe)
{
	struct def_dependency *def_dep;
	struct json_object *tmp;
	unsigned int i = 0;
	int ret;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if ((def_dep->def_dependency_type == def_dependency_software) &&
		    !def_dep->name)
			continue;
		i++;
	}

	ret = json_find_key(json_oe, "dependencies", &tmp, json_type_array);
	/* We only check the dependencies if they are present */
	if (ret)
		return 0;

	if (i != json_object_array_length(tmp))
		return -ENOENT;

	for (i = 0; i < json_object_array_length(tmp); i++) {
		struct json_object *dep = json_object_array_get_idx(tmp, i);

		CKINT(acvp_oe_match_oe_deps_matcher(dep, def_oe));
	}

out:
	return ret;
}

#endif

static int acvp_oe_match_oe(const struct acvp_testid_ctx *testid_ctx,
			    struct def_oe *def_oe,
			    struct def_dependency *def_dep,
			    struct json_object *json_oe)
{
	int ret;
	char oe_name[FILENAME_MAX];
	const char *str;

	(void)testid_ctx;
	(void)def_dep;

	CKINT(acvp_oe_generate_oe_string(def_oe, oe_name, sizeof(oe_name)));
	CKINT(json_get_string(json_oe, "name", &str));
	CKINT(acvp_str_match(oe_name, str, def_oe->acvp_oe_id));

	CKINT(acvp_oe_match_oe_deps(def_oe, json_oe));
	CKINT(acvp_oe_match_oe_depurls(testid_ctx, def_oe, json_oe));

	CKINT(json_get_string(json_oe, "url", &str));
	CKINT(acvp_get_trailing_number(str, &def_oe->acvp_oe_id));

out:
	return ret;
}

static int acvp_oe_match_cb(void *private, struct json_object *json_oe)
{
	struct acvp_oe_match_struct *matcher = private;
	int ret;

	ret = matcher->matcher(matcher->testid_ctx, matcher->def_oe,
			       matcher->def_dep, json_oe);

	/* We found a match */
	if (!ret)
		return EINTR;
	/* We found no match, yet there was no error */
	if (ret == -ENOENT)
		return 0;

	/* We received an error */
	return ret;
}

static int _acvp_oe_validate_all(
	const struct acvp_testid_ctx *testid_ctx, struct def_oe *def_oe,
	struct def_dependency *def_dep, const char *url,
	int (*matcher)(const struct acvp_testid_ctx *testid_ctx,
		       struct def_oe *def_oe, struct def_dependency *def_dep,
		       struct json_object *json_oe))
{
	struct acvp_oe_match_struct match_def;
	int ret;

	match_def.testid_ctx = testid_ctx;
	match_def.def_oe = def_oe;
	match_def.def_dep = def_dep;
	match_def.matcher = matcher;

	CKINT(acvp_paging_get(testid_ctx, url, ACVP_OPTS_SHOW_OE, &match_def,
			      &acvp_oe_match_cb));

out:
	return ret;
}

static int acvp_oe_validate_add_searchopts(const char *searchstr, char *url,
					   const unsigned int urllen)
{
	int ret;
	char queryoptions[384], str[128];

	if (!searchstr)
		return 0;

	/*
	 * Set a query option consisting of the dependency name - we OR all
	 * of them.
	 */
	CKINT(bin2hex_html(searchstr, (uint32_t)strlen(searchstr), str,
			   sizeof(str)));
	snprintf(queryoptions, sizeof(queryoptions), "name[0]=contains:%s",
		 str);
	CKINT(acvp_append_urloptions(queryoptions, url, urllen));

out:
	return ret;
}

/* GET / POST /dependencies */
static int acvp_oe_validate_all_dep(const struct acvp_testid_ctx *testid_ctx,
				    struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct def_dependency *def_dep;
	int ret = 0;
	char url[ACVP_NET_URL_MAXLEN];

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->acvp_dep_id)
			continue;

		CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url,
				      sizeof(url)));

		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			CKINT(acvp_oe_validate_add_searchopts(
				def_dep->name, url, sizeof(url)));
			CKINT(_acvp_oe_validate_all(testid_ctx, def_oe, def_dep,
						    url, acvp_oe_match_dep));
			break;
		case def_dependency_hardware:
			CKINT(acvp_oe_validate_add_searchopts(
				def_dep->proc_name, url, sizeof(url)));
			CKINT(_acvp_oe_validate_all(testid_ctx, def_oe, def_dep,
						    url, acvp_oe_match_dep));
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown type\n");
			ret = -EINVAL;
			goto out;
		}
	}

	if (ctx_opts->show_db_entries)
		goto out;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (!def_dep->acvp_dep_id) {
			if (ctx_opts->delete_db_entry & ACVP_OPTS_DELUP_OE) {
				ret = acvp_oe_register_dep(testid_ctx, def_dep,
							   acvp_http_delete,
							   false);
			} else {
				ret = acvp_oe_register_dep(testid_ctx, def_dep,
							   acvp_http_post,
							   false);
			}
			if (ret && ret != -EAGAIN)
				goto out;
		}
	}

out:
	return ret;
}

/*****************************************************************************
 * Operational Environment handler
 *****************************************************************************/

static int acvp_oe_build_oe(const struct acvp_testid_ctx *testid_ctx,
			    struct def_oe *def_oe, struct json_object **json_oe,
			    bool check_ignore_flag)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct def_dependency *def_dep;
	struct json_object *oe = NULL, *depurl = NULL, *deparray = NULL,
			   *dep = NULL;
	int ret = 0;
	char oe_name[FILENAME_MAX];
	bool depadded = false;

	if (!req_details->dump_register) {
		CKINT(acvp_oe_validate_all_dep(testid_ctx, def_oe));
	}

	oe = json_object_new_object();
	CKNULL(oe, -ENOMEM);
	CKINT(acvp_oe_generate_oe_string(def_oe, oe_name, sizeof(oe_name)));
	CKINT(json_object_object_add(oe, "name",
				     json_object_new_string(oe_name)));

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		depadded = true;

		if (def_dep->acvp_dep_id) {
			if (!depurl) {
				depurl = json_object_new_array();
				CKNULL(depurl, -ENOMEM);
				CKINT(json_object_object_add(
					oe, "dependencyUrls", depurl));
			}

			CKINT(acvp_oe_add_dep_url(def_dep->acvp_dep_id,
						  depurl));
			continue;
		}

		/*
		 * Hack for version 1 - if we have a SW dependency with the
		 * null name, skip it.
		 */
		if ((def_dep->def_dependency_type == def_dependency_software) &&
		    !def_dep->name)
			continue;

		if (!deparray) {
			deparray = json_object_new_array();
			CKNULL(deparray, -ENOMEM);
			CKINT(json_object_object_add(oe, "dependencies",
						     deparray));
		}

		switch (def_dep->def_dependency_type) {
		case def_dependency_hardware:
			CKINT(acvp_oe_build_dep_proc(def_dep, &dep,
						     check_ignore_flag));
			break;
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			CKINT(acvp_oe_build_dep_sw(def_dep, &dep,
						   check_ignore_flag));
			/*
			 * It may happen that we have a SW ID but a NULL
			 * environment name: Assume you have registered an OE
			 * with a SW dependency. But then you identified that
			 * you do not want to have a SW dependency. In this
			 * case you commonly set oeEnvName to null. You may
			 * forget to remove the SW ID from your JSON config
			 * though. In this case, the oeEnvName is defined to
			 * take precedence and we simply ignoring the SW ID in
			 * our configuration. Yet we leave the SW ID untouched
			 * and simply report that such inconsistency happened.
			 */
			if (def_dep->acvp_dep_id && !def_dep->name) {
				logger_status(
					LOGGER_C_ANY,
					"The oeEnvName is null and no OE environment is assumed to be applicable for the module. Yet, a software OE dependency ID is found in the configuration - this is an inconsistent configuration. No software OE is reported to the ACVP server\n");
			}

			break;
		default:
			ACVP_JSON_PUT_NULL(deparray);
			logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown type\n");
			ret = -EINVAL;
			goto out;
		}

		CKINT(json_object_array_add(deparray, dep));
	}

	if (!depadded) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No dependencies found for OE %s\n", oe_name);
	}

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, oe, "Vendor JSON object");

	*json_oe = oe;

	return 0;

out:
	ACVP_JSON_PUT_NULL(oe);
	return ret;
}

/* POST / PUT / DELETE /oes */
static int acvp_oe_register_oe(const struct acvp_testid_ctx *testid_ctx,
			       struct def_oe *def_oe, char *url,
			       const unsigned int urllen,
			       const enum acvp_http_type type, const bool asked)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *json_oe = NULL;
	int ret;

	/* Build JSON object with the oe specification */
	if (type != acvp_http_delete) {
		CKINT(acvp_oe_build_oe(testid_ctx, def_oe, &json_oe, asked));
	}

	if (!req_details->dump_register && !ctx_opts->register_new_oe &&
	    !asked) {
		if (json_oe) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_oe,
					JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE));
		}
		if (ask_yes("No module definition found - shall the OE be registered")) {
			ret = -ENOENT;
			goto out;
		}
	}

	CKINT(acvp_meta_register(testid_ctx, json_oe, url, urllen,
				 &def_oe->acvp_oe_id, type));

out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

/* GET /oes/<oeId> */
static int acvp_oe_validate_one_oe(const struct acvp_testid_ctx *testid_ctx,
				   struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	struct json_object *json_oe = NULL;
	struct json_object *resp = NULL, *found_data = NULL;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];
	enum acvp_http_type http_type;
	bool asked = false;

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	if (!def_oe->acvp_oe_id)
		return 0;

	logger_status(LOGGER_C_ANY,
		      "Validating operational environment reference %u\n",
		      def_oe->acvp_oe_id);

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", def_oe->acvp_oe_id));

	ret = _acvp_oe_validate_one(testid_ctx, def_oe, NULL, url, &resp,
				    &found_data, acvp_oe_match_oe);
	if (!ret)
		goto out;

	ret = acvp_search_to_http_type(ret, ACVP_OPTS_DELUP_OE, ctx_opts,
				       def_oe->acvp_oe_id, &http_type);
	if (ret == -ENOENT) {
		CKINT(acvp_oe_build_oe(testid_ctx, def_oe, &json_oe,
				       !!found_data));
		if (json_oe) {
			logger_status(
				LOGGER_C_ANY, "Data to be registered: %s\n",
				json_object_to_json_string_ext(
					json_oe,
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
				"Local meta data differs from ACVP server data - shall the ACVP data base be DELETED")) {
			http_type = acvp_http_delete;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Registering operation interrupted\n");
			goto out;
		}

		asked = true;
	} else if (ret) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Conversion from search type to HTTP request type failed for OE\n");
		goto out;
	}

	if (http_type == acvp_http_none)
		goto out;

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_oe_register_oe(testid_ctx, def_oe, url, sizeof(url),
				  http_type, asked));

out:
	ACVP_JSON_PUT_NULL(resp);
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}

/* GET / POST /oes */
static int acvp_oe_validate_all_oe(const struct acvp_testid_ctx *testid_ctx,
				   struct def_oe *def_oe)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	int ret;
	char oe_name[FILENAME_MAX - 500], url[ACVP_NET_URL_MAXLEN],
		queryoptions[FILENAME_MAX], oestr[FILENAME_MAX - 400];

	if (def_oe->acvp_oe_id)
		return 0;

	logger_status(
		LOGGER_C_ANY,
		"Searching for operational environment reference - this may take time\n");

	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));

	/* Set a query option consisting of the OE name */
	CKINT(acvp_oe_generate_oe_string(def_oe, oe_name, sizeof(oe_name)));
	CKINT(bin2hex_html(oe_name, (uint32_t)strlen(oe_name), oestr,
			   sizeof(oestr)));
	snprintf(queryoptions, sizeof(queryoptions), "name[0]=contains:%s",
		 oestr);
	CKINT(acvp_append_urloptions(queryoptions, url, sizeof(url)));

	CKINT(_acvp_oe_validate_all(testid_ctx, def_oe, NULL, url,
				    acvp_oe_match_oe));

	/* We found an entry and do not need to do anything */
	if (ret > 0 || opts->show_db_entries) {
		ret = 0;
		goto out;
	}

	/* Our vendor data does not match any vendor on ACVP server */
	CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
	CKINT(acvp_oe_register_oe(testid_ctx, def_oe, url, sizeof(url),
				  acvp_http_post, false));

out:
	return ret;
}

/*****************************************************************************
 * General handler
 *****************************************************************************/

int acvp_oe_handle_open_requests(const struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def;
	struct def_oe *def_oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor handling: testid_ctx missing\n");
	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL,
		   "Vendor handling: cipher definitions missing\n");
	def_oe = def->oe;
	CKNULL_LOG(def_oe, -EINVAL,
		   "Vendor handling: oe definitions missing\n");

	CKINT(acvp_def_get_oe_id(def_oe));

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		ret |= acvp_meta_obtain_request_result(testid_ctx,
						       &def_dep->acvp_dep_id);
	}

	ret |= acvp_meta_obtain_request_result(testid_ctx, &def_oe->acvp_oe_id);

	ret |= acvp_def_put_oe_id(def_oe);

out:
	return ret;
}

int acvp_oe_handle(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	struct def_oe *def_oe;
	struct def_dependency *def_dep;
	struct json_object *json_oe = NULL;
	int ret = 0, ret2 = 0;

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
	opts = &ctx->options;

	/* Lock def_oe */
	CKINT(acvp_def_get_oe_id(def_oe));

	/* If we have no OE with dependencies, do not handle it */
	if (!def_oe->def_dep) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "No dependencies defined - OE handling disabled\n");
		return 0;
	}

	if (req_details->dump_register) {
		char url[ACVP_NET_URL_MAXLEN];

		CKINT_ULCK(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url,
					   sizeof(url)));
		for (def_dep = def_oe->def_dep; def_dep;
		     def_dep = def_dep->next) {
			acvp_oe_register_dep(testid_ctx, def_dep,
					     acvp_http_post, false);
		}
		acvp_oe_register_oe(testid_ctx, def_oe, url, sizeof(url),
				    acvp_http_post, false);
		goto unlock;
	}

	/* Check if we have an outstanding request */
	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		ret2 |= acvp_meta_obtain_request_result(testid_ctx,
							&def_dep->acvp_dep_id);
	}

	ret2 |= acvp_meta_obtain_request_result(testid_ctx,
						&def_oe->acvp_oe_id);
	if (ret2) {
		ret = ret2;
		goto unlock;
	}

	ret = 0;
	/* Validating all dependencies if ID not present */
	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->def_dependency_type == def_dependency_software &&
		    !def_dep->name) {
			logger_status(
				LOGGER_C_ANY,
				"The oeEnvName is null and no OE environment is assumed to be applicable for the module. Yet, a software OE dependency ID is found in the configuration - this is an inconsistent configuration. No software OE is reported to the ACVP server\n");

			continue;
		}

		ret2 = acvp_oe_validate_one_dep(testid_ctx, def_oe, def_dep);
		if (ret2 == -EAGAIN)
			ret = ret2;
		else if (ret2) {
			ret = ret2;
			goto unlock;
		}
	}

	if (ret)
		goto unlock;

	if (!opts->show_db_entries) {
		/* Validating OE if ID is present */
		CKINT_ULCK(acvp_oe_validate_one_oe(testid_ctx, def_oe));
		/* Validating OE if ID is not present */
		CKINT_ULCK(acvp_oe_validate_all_oe(testid_ctx, def_oe));
		/* Validating all dependencies if ID is not present */
		CKINT_ULCK(acvp_oe_validate_all_dep(testid_ctx, def_oe));
	}

unlock:
	ret |= acvp_def_put_oe_id(def_oe);
out:
	ACVP_JSON_PUT_NULL(json_oe);
	return ret;
}
