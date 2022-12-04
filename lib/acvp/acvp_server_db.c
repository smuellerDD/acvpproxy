/*
 * Copyright (C) 2020 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "binhexbin.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"

static int _acvp_list_server_db(const struct acvp_ctx *ctx,
				const struct definition *def)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;

	CKINT(acvp_init_auth(testid_ctx));

	CKINT(acvp_sync_metadata(testid_ctx));

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}

DSO_PUBLIC
int acvp_server_db_list(const struct acvp_ctx *ctx)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	datastore = &ctx->datastore;
	search = &datastore->search;
	opts = &ctx->options;

	if (!opts->show_db_entries)
		return 0;

	/* Find a module definition */
	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	while (def) {
		CKINT(_acvp_list_server_db(ctx, def));

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

out:
	return ret;
}

static int
acvp_sever_db_prepare_search(struct acvp_ctx *ctx,
			     const enum acvp_server_db_search_type search_type,
			     unsigned int *show_type, char *url, size_t urllen)
{
	struct acvp_opts_ctx *opts = &ctx->options;
	int ret = 0;

	switch (search_type) {
	case NIST_SERVER_DB_SEARCH_VENDOR:
		CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, urllen));
		*show_type = ACVP_OPTS_SHOW_VENDOR;
		opts->show_db_entries = ACVP_OPTS_SHOW_VENDOR;
		break;
	case NIST_SERVER_DB_SEARCH_ADDRESSES:
		CKINT(acvp_create_url(NIST_VAL_OP_ADDRESSES, url, urllen));
		*show_type = ACVP_OPTS_SHOW_PERSON;
		opts->show_db_entries = ACVP_OPTS_SHOW_PERSON;
		break;
	case NIST_SERVER_DB_SEARCH_PERSONS:
		CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, urllen));
		*show_type = ACVP_OPTS_SHOW_PERSON;
		opts->show_db_entries = ACVP_OPTS_SHOW_PERSON;
		break;
	case NIST_SERVER_DB_SEARCH_OE:
		CKINT(acvp_create_url(NIST_VAL_OP_OE, url, urllen));
		*show_type = ACVP_OPTS_SHOW_OE;
		opts->show_db_entries = ACVP_OPTS_SHOW_OE;
		break;
	case NIST_SERVER_DB_SEARCH_MODULE:
		CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, urllen));
		*show_type = ACVP_OPTS_SHOW_MODULE;
		opts->show_db_entries = ACVP_OPTS_SHOW_MODULE;
		break;
	case NIST_SERVER_DB_SEARCH_DEPENDENCY:
		CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url, urllen));
		*show_type = ACVP_OPTS_SHOW_OE;
		opts->show_db_entries = ACVP_OPTS_SHOW_OE;
		break;
	case NIST_SERVER_DB_SEARCH_VALIDATION:
		CKINT(acvp_create_url(NIST_VAL_OP_VALIDATIONS, url, urllen));
		*show_type = ACVP_OPTS_SHOW_VALIDATION;
		opts->show_db_entries = ACVP_OPTS_SHOW_VALIDATION;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown search type %u\n",
		       search_type);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

DSO_PUBLIC
int acvp_server_db_search(struct acvp_ctx *ctx,
			  const enum acvp_server_db_search_type search_type,
			  const char *searchstr)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	unsigned int show_type;
	int ret;
	char url[ACVP_NET_URL_MAXLEN], searchstr_html[128];

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");
	CKNULL_LOG(search_type, -EINVAL, "No search type provided\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	CKINT(acvp_sever_db_prepare_search(ctx, search_type, &show_type, url,
					   sizeof(url)));

	/* Set a query option consisting of vendor_name */
	CKINT(bin2hex_html_from_url(searchstr, (uint32_t)strlen(searchstr),
				    searchstr_html, sizeof(searchstr_html)));
	CKINT(acvp_append_urloptions(searchstr_html, url, sizeof(url)));

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->ctx = ctx;

	CKINT(acvp_init_auth(testid_ctx));

	CKINT(acvp_paging_get(testid_ctx, url, show_type, NULL, NULL));

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}

static int
_acvp_server_db_fetch_id(struct acvp_ctx *ctx,
			 const enum acvp_server_db_search_type search_type,
			 const uint32_t id, struct acvp_buf *response)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	unsigned int show_type;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");
	CKNULL_LOG(search_type, -EINVAL, "No search type provided\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	CKINT(acvp_sever_db_prepare_search(ctx, search_type, &show_type, url,
					   sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", id));

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->ctx = ctx;

	CKINT(acvp_init_auth(testid_ctx));

	CKINT(acvp_net_op(testid_ctx, url, NULL, response, acvp_http_get));

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}

DSO_PUBLIC
int acvp_server_db_fetch_id(struct acvp_ctx *ctx,
			    const enum acvp_server_db_search_type search_type,
			    const uint32_t id)
{
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(response);
	int ret;

	CKINT(_acvp_server_db_fetch_id(ctx, search_type, id, &response));

	CKINT(acvp_req_strip_version(&response, &req, &entry));

	fprintf(stdout, "ACVP Server DB Entry:\n%s\n",
		json_object_to_json_string_ext(
			entry, JSON_C_TO_STRING_PRETTY |
				       JSON_C_TO_STRING_NOSLASHESCAPE));

out:
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);

	return ret;
}

static int acvp_server_db_config_dir(char *pathname, size_t pathnamelen)
{
	struct stat statbuf;
	int ret;

	snprintf(pathname, pathnamelen, "%s", ACVP_DEF_DEFAULT_CONFIG_DIR);

	CKINT(acvp_datastore_file_dir(pathname, true));

	if (stat(pathname, &statbuf))
		return -errno;

out:
	return ret;
}

static int acvp_server_db_read_json(struct json_object **config,
				    const char *pathname)
{
	struct stat statbuf;
	struct json_object *filecontent;
	int ret = 0, fd;

	if (stat(pathname, &statbuf)) {
		struct json_object *o = json_object_new_object();

		CKNULL(o, -ENOMEM);
		*config = o;
		goto out;
	}

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -errno;

	filecontent = json_object_from_fd(fd);

	close(fd);

	CKNULL(filecontent, -EFAULT);
	*config = filecontent;

out:
	return ret;
}

static int acvp_server_db_write_json(struct json_object *config,
				     const char *pathname)
{
	int ret, fd, errsv;

	fd = open(pathname, O_WRONLY | O_TRUNC);
	errsv = errno;
	if (fd < 0 && errsv == ENOENT)
		fd = open(pathname, O_WRONLY | O_CREAT, 0777);
	if (fd < 0)
		return -errsv;

	ret = json_object_to_fd(fd, config,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE);

	close(fd);

	return ret;
}

static int acvp_server_db_add_config(const char *pathname, const char *key,
				     const char *str)
{
	struct json_object *config = NULL;
	struct json_object *val;
	int ret;

	CKINT_LOG(acvp_server_db_read_json(&config, pathname),
		  "Cannot parse module config file %s\n", pathname);
	if (json_find_key(config, key, &val, json_type_string) &&
	    json_find_key(config, key, &val, json_type_int)) {
		CKINT(json_object_object_add(config, key,
					     json_object_new_string(str)));
	} else {
		CKINT(json_object_set_string(val, str));
	}

	CKINT(acvp_server_db_write_json(config, pathname));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

static int acvp_server_db_process_vendor(struct acvp_ctx *ctx,
					 const char *configdir,
					 struct def_info *info)
{
	struct def_vendor vendor;
	struct json_object *req = NULL, *entry = NULL, *addr, *tmp;
	ACVP_BUFFER_INIT(response);
	char pathname[FILENAME_MAX];
	const char *str;
	int ret;

	memset(&vendor, 0, sizeof(vendor));

	CKINT(acvp_def_alloc_lock(&vendor.def_lock));

	vendor.acvp_vendor_id = info->acvp_vendor_id;
	vendor.acvp_addr_id = info->acvp_addr_id;
	vendor.acvp_person_id = info->acvp_person_id;

	CKINT(_acvp_server_db_fetch_id(ctx, NIST_SERVER_DB_SEARCH_VENDOR,
				       info->acvp_vendor_id, &response));
	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_get_string(entry, "name", &str));
	CKINT(acvp_duplicate(&vendor.vendor_name, str));
	CKINT(acvp_duplicate(&vendor.vendor_name_filesafe, str));
	CKINT(acvp_sanitize_string(vendor.vendor_name_filesafe));

	snprintf(pathname, sizeof(pathname), "%s", configdir);
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 ACVP_DEF_DIR_VENDOR));
	CKINT(acvp_datastore_file_dir(pathname, true));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 vendor.vendor_name_filesafe));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), ".json"));
	CKINT(acvp_duplicate(&vendor.def_vendor_file, pathname));

	CKINT(acvp_server_db_add_config(pathname, "vendorName",
					vendor.vendor_name));

	CKINT(json_get_string(entry, "website", &str));
	CKINT(acvp_duplicate(&vendor.vendor_url, str));
	CKINT(acvp_server_db_add_config(pathname, "vendorUrl",
					vendor.vendor_url));

	CKINT(json_find_key(entry, "addresses", &addr, json_type_array));
	tmp = json_object_array_get_idx(addr, 0);
	CKNULL(str, -ENOENT);

	CKINT(json_get_string(tmp, "street1", &str));
	CKINT(acvp_duplicate(&vendor.addr_street, str));
	CKINT(acvp_server_db_add_config(pathname, "addressStreet",
					vendor.addr_street));

	CKINT(json_get_string(tmp, "locality", &str));
	CKINT(acvp_duplicate(&vendor.addr_locality, str));
	CKINT(acvp_server_db_add_config(pathname, "addressCity",
					vendor.addr_locality));

	if (!json_get_string(tmp, "region", &str)) {
		CKINT(acvp_duplicate(&vendor.addr_region, str));
		CKINT(acvp_server_db_add_config(pathname, "addressState",
						vendor.addr_region));
	}

	CKINT(json_get_string(tmp, "country", &str));
	CKINT(acvp_duplicate(&vendor.addr_country, str));
	CKINT(acvp_server_db_add_config(pathname, "addressCountry",
					vendor.addr_country));

	CKINT(json_get_string(tmp, "postalCode", &str));
	CKINT(acvp_duplicate(&vendor.addr_zipcode, str));
	CKINT(acvp_server_db_add_config(pathname, "addressZip",
					vendor.addr_zipcode));

	CKINT(acvp_def_put_vendor_id(&vendor));

	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(req);

	CKINT(_acvp_server_db_fetch_id(ctx, NIST_SERVER_DB_SEARCH_PERSONS,
				       info->acvp_person_id, &response));
	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_get_string(entry, "fullName", &str));
	CKINT(acvp_duplicate(&vendor.contact_name, str));
	CKINT(acvp_server_db_add_config(pathname, "contactName",
					vendor.contact_name));

	CKINT(json_find_key(entry, "emails", &addr, json_type_array));
	str = json_object_get_string(json_object_array_get_idx(addr, 0));
	CKNULL(str, -ENOENT);
	CKINT(acvp_duplicate(&vendor.contact_email, str));
	CKINT(acvp_server_db_add_config(pathname, "contactEmail",
					vendor.contact_email));

	if (!json_find_key(entry, "phoneNumbers", &addr, json_type_array)) {
		tmp = json_object_array_get_idx(addr, 0);
		CKNULL(tmp, -ENOENT);
		CKINT(json_get_string(tmp, "number", &str));
		CKINT(acvp_duplicate(&vendor.contact_phone, str));
		CKINT(acvp_server_db_add_config(pathname, "contactPhone",
						vendor.contact_phone));
	}

	CKINT(acvp_def_put_person_id(&vendor));

out:
	acvp_def_free_vendor(&vendor);
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

static int acvp_server_db_process_module(struct acvp_ctx *ctx, char *configdir,
					 size_t configdirlen,
					 const struct json_object *module_entry)
{
	struct def_info info;
	struct json_object *contact;
	char pathname[FILENAME_MAX];
	const char *str;
	int ret;

	memset(&info, 0, sizeof(info));

	CKINT(acvp_def_alloc_lock(&info.def_lock));

	CKINT(json_get_string(module_entry, "name", &str));
	CKINT(acvp_duplicate(&info.module_name, str));
	CKINT(acvp_duplicate(&info.orig_module_name, str));
	CKINT(acvp_duplicate(&info.module_name_filesafe, str));
	CKINT(acvp_sanitize_string(info.module_name_filesafe));

	CKINT(acvp_extend_string(configdir, configdirlen, "/%s",
				 info.module_name_filesafe));
	CKINT(acvp_datastore_file_dir(configdir, true));

	snprintf(pathname, sizeof(pathname), "%s", configdir);
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 ACVP_DEF_DIR_MODINFO));
	CKINT(acvp_datastore_file_dir(pathname, true));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 info.module_name_filesafe));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), ".json"));
	CKINT(acvp_duplicate(&info.def_module_file, pathname));

	CKINT(acvp_server_db_add_config(pathname, "moduleName",
					info.module_name));

	CKINT(json_get_string(module_entry, "version", &str));
	CKINT(acvp_duplicate(&info.module_version, str));
	CKINT(acvp_duplicate(&info.module_version_filesafe, str));
	CKINT(acvp_sanitize_string(info.module_version_filesafe));
	CKINT(acvp_server_db_add_config(pathname, "moduleVersion",
					info.module_version));

	CKINT(json_get_string(module_entry, "description", &str));
	CKINT(acvp_duplicate(&info.module_description, str));
	CKINT(acvp_server_db_add_config(pathname, "moduleDescription",
					info.module_description));

	CKINT(json_get_string(module_entry, "type", &str));
	CKINT(acvp_module_type_name_to_enum(str, &info.module_type));
	CKINT(acvp_server_db_add_config(pathname, "moduleType", str));

	CKINT(json_get_string(module_entry, "url", &str));
	CKINT(acvp_get_trailing_number(str, &info.acvp_module_id));

	CKINT(json_get_string(module_entry, "vendorUrl", &str));
	CKINT(acvp_get_trailing_number(str, &info.acvp_vendor_id));

	CKINT(json_get_string(module_entry, "addressUrl", &str));
	CKINT(acvp_get_trailing_number(str, &info.acvp_addr_id));

	CKINT(json_find_key(module_entry, "contactUrls", &contact,
			    json_type_array));
	str = json_object_get_string(json_object_array_get_idx(contact, 0));
	CKNULL(str, -ENOENT);
	CKINT(acvp_get_trailing_number(str, &info.acvp_person_id));

	CKINT(acvp_def_put_module_id(&info));

	CKINT(acvp_server_db_process_vendor(ctx, configdir, &info));

out:
	acvp_def_free_info(&info);
	return ret;
}

static int
acvp_server_db_process_validation(struct acvp_ctx *ctx, char *configdir,
				  size_t configdirlen,
				  const struct json_object *validation_entry)
{
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(response);
	uint32_t id;
	const char *str;
	int ret;

	/* Module definition */
	CKINT(json_get_string(validation_entry, "moduleUrl", &str));
	CKINT(acvp_get_trailing_number(str, &id));

	CKINT(_acvp_server_db_fetch_id(ctx, NIST_SERVER_DB_SEARCH_MODULE, id,
				       &response));
	CKINT(acvp_req_strip_version(&response, &req, &entry));
	CKINT(acvp_server_db_process_module(ctx, configdir, configdirlen,
					    entry));
	ACVP_JSON_PUT_NULL(req);

out:
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

static int acvp_server_db_write_def(const struct def_dependency *def_dep,
				    struct json_object *dep_entry)
{
	const char *type_name;
	int ret;

	CKINT(acvp_dep_type2name(def_dep->def_dependency_type, &type_name));
	CKINT(json_object_object_add(dep_entry, "dependencyType",
				     json_object_new_string(type_name)));

	switch (def_dep->def_dependency_type) {
	case def_dependency_firmware:
	case def_dependency_os:
	case def_dependency_software:
		if (def_dep->name) {
			CKINT(json_object_object_add(
				dep_entry, "oeEnvName",
				json_object_new_string(def_dep->name)));
		} else {
			CKINT(json_object_object_add(dep_entry, "oeEnvName",
						     NULL));
		}

		if (def_dep->cpe)
			CKINT(json_object_object_add(
				dep_entry, "cpe",
				json_object_new_string(def_dep->cpe)));
		if (def_dep->swid)
			CKINT(json_object_object_add(
				dep_entry, "swid",
				json_object_new_string(def_dep->swid)));

		if (def_dep->description)
			CKINT(json_object_object_add(
				dep_entry, "oe_description",
				json_object_new_string(def_dep->description)));
		break;
	case def_dependency_hardware:
		if (def_dep->manufacturer)
			CKINT(json_object_object_add(
				dep_entry, "manufacturer",
				json_object_new_string(def_dep->manufacturer)));
		if (def_dep->proc_family)
			CKINT(json_object_object_add(
				dep_entry, "procFamily",
				json_object_new_string(def_dep->proc_family)));
		if (def_dep->proc_name)
			CKINT(json_object_object_add(
				dep_entry, "procName",
				json_object_new_string(def_dep->proc_name)));
		if (def_dep->proc_series)
			CKINT(json_object_object_add(
				dep_entry, "procSeries",
				json_object_new_string(def_dep->proc_series)));

		//TODO features is not created
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE dependency type\n");
		ret = -EFAULT;
		goto out;
	}

out:
	return ret;
}

static int acvp_server_db_write_oe_config(const char *pathname,
					  const struct def_oe *def_oe)
{
	const struct def_dependency *def_dep;
	struct json_object *oe = json_object_new_object();
	struct json_object *dep_array, *dep;
	int ret;

	CKNULL(oe, -ENOMEM);

	dep_array = json_object_new_array();
	CKNULL(dep_array, -ENOMEM);
	CKINT(json_object_object_add(oe, "oeDependencies", dep_array));

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		dep = json_object_new_object();
		CKNULL(dep, -ENOMEM);
		CKINT(json_object_array_add(dep_array, dep));

		CKINT(acvp_server_db_write_def(def_dep, dep));
	}

	json_logger(LOGGER_DEBUG, LOGGER_C_ANY, oe, "writing data");

	CKINT(acvp_server_db_write_json(oe, pathname));

out:
	ACVP_JSON_PUT_NULL(oe);
	return ret;
}

static int acvp_server_db_process_one_oe(struct acvp_ctx *ctx,
					 const char *configdir, uint32_t id)
{
	struct def_oe def_oe;
	struct def_dependency *def_dep;
	struct json_object *req = NULL, *entry = NULL, *deps;
	ACVP_BUFFER_INIT(response);
	char pathname[FILENAME_MAX];
	char *sanitized_name = NULL;
	const char *str;
	unsigned int i;
	int ret;

	memset(&def_oe, 0, sizeof(def_oe));

	CKINT(acvp_def_alloc_lock(&def_oe.def_lock));

	def_oe.acvp_oe_id = id;
	def_oe.config_file_version = 2;

	CKINT(_acvp_server_db_fetch_id(ctx, NIST_SERVER_DB_SEARCH_OE, id,
				       &response));
	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_get_string(entry, "name", &str));
	CKINT(acvp_duplicate(&sanitized_name, str));
	CKINT(acvp_sanitize_string(sanitized_name));

	snprintf(pathname, sizeof(pathname), "%s", configdir);
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 ACVP_DEF_DIR_OE));
	CKINT(acvp_datastore_file_dir(pathname, true));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), "/%s",
				 sanitized_name));
	CKINT(acvp_extend_string(pathname, sizeof(pathname), ".json"));
	CKINT(acvp_duplicate(&def_oe.def_oe_file, pathname));

	CKINT(json_find_key(entry, "dependencies", &deps, json_type_array));
	for (i = 0; i < json_object_array_length(deps); i++) {
		struct json_object *dep = json_object_array_get_idx(deps, i);

		if (!dep)
			break;

		def_dep = calloc(1, sizeof(*def_dep));
		CKNULL(def_dep, -ENOMEM);

		if (def_oe.def_dep) {
			struct def_dependency *tmp = def_oe.def_dep;

			while (tmp) {
				if (!tmp->next) {
					tmp->next = def_dep;
					break;
				}
				tmp = tmp->next;
			}
		} else {
			def_oe.def_dep = def_dep;
		}

		if (!json_get_string(dep, "type", &str)) {
			ret = acvp_dep_name2type(str,
						 &def_dep->def_dependency_type);
			if (ret < 0) {
				logger(LOGGER_WARN, LOGGER_C_ANY,
				       "dependencyType %s is unknown - using default of hardware!\n",
				       str);
				def_dep->def_dependency_type =
					def_dependency_hardware;
			}
		}

		CKINT(json_get_string(dep, "url", &str));
		CKINT(acvp_get_trailing_number(str, &def_dep->acvp_dep_id));

		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			if (!json_get_string(dep, "cpe", &str))
				CKINT(acvp_duplicate(&def_dep->cpe, str));
			if (!json_get_string(dep, "swid", &str))
				CKINT(acvp_duplicate(&def_dep->swid, str));
			if (!json_get_string(dep, "description", &str)) {
				CKINT(acvp_duplicate(&def_dep->description,
						     str));
				if (!json_get_string(dep, "name", &str))
					CKINT(acvp_duplicate(&def_dep->name,
							     str));
			}
			break;
		case def_dependency_hardware:
			if (!json_get_string(dep, "manufacturer", &str))
				CKINT(acvp_duplicate(&def_dep->manufacturer,
						     str));

			if (!json_get_string(dep, "family", &str))
				CKINT(acvp_duplicate(&def_dep->proc_family,
						     str));

			if (!json_get_string(dep, "series", &str))
				CKINT(acvp_duplicate(&def_dep->proc_series,
						     str));
			if (!json_get_string(dep, "name", &str))
				CKINT(acvp_duplicate(&def_dep->proc_name, str));
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			ret = -EFAULT;
			goto out;
		}
	}

	CKINT(acvp_server_db_write_oe_config(pathname, &def_oe));

	CKINT(acvp_def_put_oe_id(&def_oe));

out:
	if (sanitized_name)
		free(sanitized_name);
	acvp_def_free_oe(&def_oe);
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

static int acvp_server_db_process_oe(struct acvp_ctx *ctx,
				     const char *configdir,
				     const struct json_object *validation_entry)
{
	struct json_object *oe;
	ACVP_BUFFER_INIT(response);
	unsigned int i;
	int ret;

	CKINT(json_find_key(validation_entry, "oeUrls", &oe, json_type_array));

	for (i = 0; i < json_object_array_length(oe); i++) {
		uint32_t id;
		const char *str = json_object_get_string(
			json_object_array_get_idx(oe, i));

		if (!str)
			break;

		CKINT(acvp_get_trailing_number(str, &id));
		CKINT(acvp_server_db_process_one_oe(ctx, configdir, id));
	}

out:
	acvp_free_buf(&response);
	return ret;
}

DSO_PUBLIC
int acvp_server_db_fetch_validation(struct acvp_ctx *ctx, const uint32_t id)
{
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(response);
	char configdir[255];
	int ret;

	CKINT(acvp_server_db_config_dir(configdir, sizeof(configdir)));

	/* Search validation */
	CKINT(_acvp_server_db_fetch_id(ctx, NIST_SERVER_DB_SEARCH_VALIDATION,
				       id, &response));
	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(acvp_server_db_process_validation(ctx, configdir,
						sizeof(configdir), entry));
	CKINT(acvp_server_db_process_oe(ctx, configdir, entry));

out:
	acvp_free_buf(&response);
	ACVP_JSON_PUT_NULL(req);
	return ret;
}
