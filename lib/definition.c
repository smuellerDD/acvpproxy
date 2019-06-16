/* ACVP definition handling
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

#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "acvpproxy.h"
#include "definition.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "mutex.h"

/* List of instantiated module definitions */
static DEFINE_MUTEX_UNLOCKED(def_mutex);
static struct definition *def_head = NULL;

/* List of uninstantiated module definitions */
static DEFINE_MUTEX_UNLOCKED(def_uninstantiated_mutex);
static struct def_algo_map *def_uninstantiated_head = NULL;

static DEFINE_MUTEX_UNLOCKED(def_file_access_mutex);

/*****************************************************************************
 * Handle refcnt lock
 *****************************************************************************/
static int acvp_def_alloc_lock(struct def_lock **lock)
{
	struct def_lock *tmp;
	int ret = 0;

	tmp = calloc(1, sizeof(*tmp));
	CKNULL(tmp, -ENOMEM);

	mutex_init(&tmp->lock, 0);
	atomic_set(0, &tmp->refcnt);

	*lock = tmp;

out:
	return ret;
}

static void acvp_def_get_lock(struct def_lock *lock)
{
	atomic_inc(&lock->refcnt);
}

static void acvp_def_lock_lock(struct def_lock *lock)
{
	mutex_lock(&lock->lock);
}

static void acvp_def_lock_unlock(struct def_lock *lock)
{
	mutex_unlock(&lock->lock);
}

static void acvp_def_put_lock(struct def_lock *lock)
{
	if (!lock)
		return;

	/* Free if lock was not used so far (e.g. uninstantiated defs) */
	if (!atomic_read(&lock->refcnt)) {
		free(lock);
		return;
	}

	/* Free if refcount is zero. */
	if (atomic_dec_and_test(&lock->refcnt))
		free(lock);
}

static void acvp_def_dealloc_unused_lock(struct def_lock *lock)
{
	if (!lock)
		return;

	if (!atomic_read(&lock->refcnt)) {
		free(lock);
		return;
	}
}

/*****************************************************************************
 * Runtime registering code for cipher definitions
 *****************************************************************************/

/**
 * @brief Register one cipher module implementation with the library. This
 *	  function is intended to be invoked in the constructor of the library,
 *	  i.e. in a function that is marked with the ACVP_DEFINE_CONSTRUCTOR
 *	  macro to allow an automatic invocation of the register operation
 *	  during load time of the library.
 *
 * @param curr_def Pointer to the definition to be registered.
 */
static void acvp_register_def(struct definition *curr_def)
{
	struct definition *tmp_def;

	/* Safety-measure to prevent programming bugs to affect us. */
	curr_def->next = NULL;

	mutex_lock(&def_mutex);
	if (!def_head) {
		def_head = curr_def;
		goto out;
	}

	for (tmp_def = def_head; tmp_def != NULL; tmp_def = tmp_def->next) {
		/* do not re-register */
		if (curr_def == tmp_def) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Programming bug: re-registering definition!\n");
			goto out;
		}

		if (!tmp_def->next) {
			tmp_def->next = curr_def;
			goto out;
		}
	}

out:
	mutex_unlock(&def_mutex);
	return;
}

/* Return true when a match is found, otherwise false */
static bool acvp_find_match(const char *searchstr, const char *defstr,
			    bool fuzzy_search)
{
	/* If no searchstring is provided, we match */
	if (!searchstr)
		return true;

	if (fuzzy_search) {
		/* We perform a substring search */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Fuzzy search for %s in string %s\n", searchstr, defstr);

		if (strstr(defstr, searchstr))
			return true;
		else
			return false;
	} else {
		/* Exact search */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Exact search for %s in string %s\n", searchstr, defstr);

		if (strncmp(searchstr, defstr, strlen(defstr)))
			return false;
		else
			return true;
	}
}

struct definition *acvp_find_def(const struct acvp_search_ctx *search,
				 struct definition *processed_ptr)
{
	struct definition *tmp_def = NULL;

	mutex_reader_lock(&def_mutex);

	if (processed_ptr) {
		/*
		 * Guarantee that the pointer is valid as we unlock the mutex
		 * when returning.
		 */
		for (tmp_def = def_head;
		     tmp_def != NULL;
		     tmp_def = tmp_def->next) {
			if (tmp_def == processed_ptr)
				break;
		}

		if (!tmp_def) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Processed pointer is not known to definition list! - Programming Bug at file %s line %d\n",
			       __FILE__, __LINE__);
			goto out;
		}

		tmp_def = processed_ptr->next;
	} else {
		tmp_def = def_head;
	}

	for ( ; tmp_def != NULL; tmp_def = tmp_def->next) {
		const struct def_vendor *vendor = tmp_def->vendor;
		const struct def_info *mod_info = tmp_def->info;
		const struct def_oe *oe = tmp_def->oe;

		if (!acvp_find_match(search->modulename,
				     mod_info->module_name,
				     search->fuzzy_name_search))
			continue;

		if (!acvp_find_match(search->moduleversion,
				     mod_info->module_version,
				     search->fuzzy_name_search))
			continue;

		if (!acvp_find_match(search->vendorname,
				     vendor->vendor_name,
				     search->fuzzy_name_search))
			continue;

		if (!acvp_find_match(search->execenv,
				     oe->oe_env_name,
				     search->fuzzy_name_search))
			continue;

		if (!acvp_find_match(search->processor,
				     oe->proc_name,
				     search->fuzzy_name_search))
			continue;

		break;
	}

out:
	mutex_reader_unlock(&def_mutex);
	return tmp_def;
}

int acvp_export_def_search(struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def = testid_ctx->def;
	const struct def_vendor *vendor;
	const struct def_info *mod_info;
	const struct def_oe *oe;
	struct json_object *s = NULL;
	ACVP_BUFFER_INIT(tmp);
	int ret;
	const char *str;

	CKNULL_LOG(def, -EINVAL, "Module definition context missing\n");
	vendor = def->vendor;
	mod_info = def->info;
	oe = def->oe;

	s = json_object_new_object();
	CKNULL(s, -ENOMEM);

	CKINT(json_object_object_add(s, "moduleName",
			json_object_new_string(mod_info->module_name)));
	CKINT(json_object_object_add(s, "moduleVersion",
			json_object_new_string(mod_info->module_version)));
	CKINT(json_object_object_add(s, "vendorName",
			json_object_new_string(vendor->vendor_name)));
	CKINT(json_object_object_add(s, "execenv",
			json_object_new_string(oe->oe_env_name)));
	CKINT(json_object_object_add(s, "processor",
			json_object_new_string(oe->proc_name)));

	/* Convert the JSON buffer into a string */
	str = json_object_to_json_string_ext(s, JSON_C_TO_STRING_PRETTY  |
					     JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(str, -EFAULT,
		   "JSON object conversion into string failed\n");

	/* Write the JSON data to disk */
	tmp.buf = (uint8_t *)str;
	tmp.len = strlen(str);
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, ACVP_DS_DEF_REFERENCE,
					      true, &tmp));

out:
	ACVP_JSON_PUT_NULL(s);
	return ret;
}

int acvp_match_def(const struct acvp_testid_ctx *testid_ctx,
		   struct json_object *def_config)
{
	const struct definition *def = testid_ctx->def;
	const struct def_vendor *vendor = def->vendor;
	const struct def_info *mod_info = def->info;
	const struct def_oe *oe = def->oe;
	struct acvp_search_ctx search;
	int ret;

	memset(&search, 0, sizeof(search));
	CKINT(json_get_string(def_config, "moduleName",
			      (const char **)&search.modulename));
	CKINT(json_get_string(def_config, "moduleVersion",
			      (const char **)&search.moduleversion));
	CKINT(json_get_string(def_config, "vendorName",
			      (const char **)&search.vendorname));
	CKINT(json_get_string(def_config, "execenv",
			      (const char **)&search.execenv));
	CKINT(json_get_string(def_config, "processor",
			      (const char **)&search.processor));

	if (!acvp_find_match(search.modulename, mod_info->module_name, false) ||
	    !acvp_find_match(search.moduleversion, mod_info->module_version,
			     false) ||
	    !acvp_find_match(search.vendorname, vendor->vendor_name, false) ||
	    !acvp_find_match(search.execenv, oe->oe_env_name, false) ||
	    !acvp_find_match(search.processor, oe->proc_name, false)) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search does not match with old search\n",
		       testid_ctx->testid);
		ret = -ENOENT;
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search matches with old search\n",
		       testid_ctx->testid);
		ret = 0;
	}

out:
	return ret;
}

DSO_PUBLIC
int acvp_list_unregistered_definitions(void)
{
	struct def_algo_map *map = NULL;

	fprintf(stderr, "Algo Name | Processor | Implementation Name\n");

	mutex_reader_lock(&def_uninstantiated_mutex);

	for (map = def_uninstantiated_head; map != NULL; map = map->next)
		fprintf(stderr, "%s | %s | %s\n",
			map->algo_name, map->processor, map->impl_name);

	mutex_reader_unlock(&def_uninstantiated_mutex);

	fprintf(stderr, "\nUse this information to create instantiations by module definition configuration files\n");

	return 0;
}

DSO_PUBLIC
int acvp_list_registered_definitions(const struct acvp_search_ctx *search)
{
	struct definition *def;
	unsigned int vsid = 0;
	int found = 0;

	fprintf(stderr, "Vendor Name | Operational Environment | Processor | Module Name | Module Version | vsIDs\n");

	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	while (def) {
		const struct def_info *mod_info = def->info;
		const struct def_vendor *vendor = def->vendor;
		const struct def_oe *oe = def->oe;

		fprintf(stderr, "%s | %s | %s | %s | %s | %u\n",
			vendor->vendor_name, oe->oe_env_name, oe->proc_name,
			mod_info->module_name, mod_info->module_version,
			def->num_algos);
		found = 1;

		vsid += def->num_algos;

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

	fprintf(stderr,
		"====================================================\n");
	fprintf(stderr,
		"Expected numbers of vsIDs for listed definitions: %u\n", vsid);

	if (!found)
		fprintf(stderr, "none\n");

	return 0;
}

static void acvp_def_del_info(struct definition *def)
{
	struct def_info *info;

	if (!def || !def->info)
		return;

	info = def->info;

	ACVP_PTR_FREE_NULL(info->module_name);
	ACVP_PTR_FREE_NULL(info->module_name_filesafe);
	ACVP_PTR_FREE_NULL(info->module_version);
	ACVP_PTR_FREE_NULL(info->module_version_filesafe);
	ACVP_PTR_FREE_NULL(info->module_description);
	ACVP_PTR_FREE_NULL(info->def_module_file);
	acvp_def_put_lock(info->def_lock);
	ACVP_PTR_FREE_NULL(def->info);
}

static void acvp_def_del_vendor(struct definition *def)
{
	struct def_vendor *vendor;

	if (!def || !def->vendor)
		return;

	vendor = def->vendor;

	ACVP_PTR_FREE_NULL(vendor->vendor_name);
	ACVP_PTR_FREE_NULL(vendor->vendor_name_filesafe);
	ACVP_PTR_FREE_NULL(vendor->vendor_url);
	ACVP_PTR_FREE_NULL(vendor->contact_name);
	ACVP_PTR_FREE_NULL(vendor->contact_email);
	ACVP_PTR_FREE_NULL(vendor->contact_phone);
	ACVP_PTR_FREE_NULL(vendor->addr_street);
	ACVP_PTR_FREE_NULL(vendor->addr_locality);
	ACVP_PTR_FREE_NULL(vendor->addr_region);
	ACVP_PTR_FREE_NULL(vendor->addr_country);
	ACVP_PTR_FREE_NULL(vendor->addr_zipcode);
	ACVP_PTR_FREE_NULL(vendor->def_vendor_file);
	acvp_def_put_lock(vendor->def_lock);
	ACVP_PTR_FREE_NULL(def->vendor);
}

static void acvp_def_del_oe(struct definition *def)
{
	struct def_oe *oe;

	if (!def || !def->oe)
		return;

	oe = def->oe;

	ACVP_PTR_FREE_NULL(oe->oe_env_name);
	ACVP_PTR_FREE_NULL(oe->cpe);
	ACVP_PTR_FREE_NULL(oe->swid);
	ACVP_PTR_FREE_NULL(oe->oe_description);
	ACVP_PTR_FREE_NULL(oe->manufacturer);
	ACVP_PTR_FREE_NULL(oe->proc_family);
	ACVP_PTR_FREE_NULL(oe->proc_name);
	ACVP_PTR_FREE_NULL(oe->proc_series);
	ACVP_PTR_FREE_NULL(oe->def_oe_file);
	acvp_def_put_lock(oe->def_lock);
	ACVP_PTR_FREE_NULL(def->oe);
}

static int acvp_def_add_info(struct definition *def, struct def_info *src,
			     const char *impl_name)
{
	struct def_info *info;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");

	info = calloc(1, sizeof(*info));
	CKNULL(info, -ENOMEM);
	def->info = info;

	if (impl_name) {
		uint32_t len = strlen(src->module_name) + strlen(impl_name) + 4;

		info->module_name = malloc(len);
		CKNULL(info->module_name, -ENOMEM);
		snprintf(info->module_name, len, "%s (%s)", src->module_name,
			 impl_name);
	} else {
		info->module_name = strdup(src->module_name);
		CKNULL(info->module_name, -ENOMEM);
	}
	CKINT(acvp_duplicate(&info->module_name_filesafe, info->module_name));

	CKINT(acvp_duplicate(&info->module_version, src->module_version));
	CKINT(acvp_duplicate(&info->module_version_filesafe,
			     info->module_version));

	CKINT(acvp_duplicate(&info->module_description,
			     src->module_description));
	info->module_type = src->module_type;

	CKINT(acvp_duplicate(&info->def_module_file, src->def_module_file));

	/* Use a global lock for all module definitions */
	info->def_lock = src->def_lock;
	acvp_def_get_lock(info->def_lock);

	/* We do not read the module ID here. */

out:
	if (ret)
		acvp_def_del_info(def);
	return ret;
}

static int acvp_def_add_vendor(struct definition *def, struct def_vendor *src)
{
	struct def_vendor *vendor;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");

	vendor = calloc(1, sizeof(*vendor));
	CKNULL(vendor, -ENOMEM);
	def->vendor = vendor;

	CKINT(acvp_duplicate(&vendor->vendor_name, src->vendor_name));
	CKINT(acvp_duplicate(&vendor->vendor_name_filesafe, src->vendor_name));
	CKINT(acvp_sanitize_string(vendor->vendor_name_filesafe));

	CKINT(acvp_duplicate(&vendor->vendor_url, src->vendor_url));
	CKINT(acvp_duplicate(&vendor->contact_name, src->contact_name));
	CKINT(acvp_duplicate(&vendor->contact_email, src->contact_email));
	CKINT(acvp_duplicate(&vendor->contact_phone, src->contact_phone));
	CKINT(acvp_duplicate(&vendor->addr_street, src->addr_street));
	CKINT(acvp_duplicate(&vendor->addr_locality, src->addr_locality));
	CKINT(acvp_duplicate(&vendor->addr_region, src->addr_region));
	CKINT(acvp_duplicate(&vendor->addr_country, src->addr_country));
	CKINT(acvp_duplicate(&vendor->addr_zipcode, src->addr_zipcode));

	CKINT(acvp_duplicate(&vendor->def_vendor_file, src->def_vendor_file));

	/* Use a global lock for all vendor definitions */
	vendor->def_lock = src->def_lock;
	acvp_def_get_lock(vendor->def_lock);

out:
	if (ret)
		acvp_def_del_vendor(def);
	return ret;
}

static int acvp_def_add_oe(struct definition *def, struct def_oe *src)
{
	struct def_oe *oe;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");

	oe = calloc(1, sizeof(*oe));
	CKNULL(oe, -ENOMEM);
	def->oe = oe;

	oe->env_type = src->env_type;
	CKINT(acvp_duplicate(&oe->oe_env_name, src->oe_env_name));
	CKINT(acvp_duplicate(&oe->cpe, src->cpe));
	CKINT(acvp_duplicate(&oe->swid, src->swid));
	CKINT(acvp_duplicate(&oe->oe_description, src->oe_description));
	CKINT(acvp_duplicate(&oe->manufacturer, src->manufacturer));
	CKINT(acvp_duplicate(&oe->proc_family, src->proc_family));
	CKINT(acvp_duplicate(&oe->proc_name, src->proc_name));
	CKINT(acvp_duplicate(&oe->proc_series, src->proc_series));
	oe->features = src->features;

	CKINT(acvp_duplicate(&oe->def_oe_file, src->def_oe_file));

	oe->acvp_oe_dep_proc_id = src->acvp_oe_dep_proc_id;
	oe->acvp_oe_dep_sw_id = src->acvp_oe_dep_sw_id;
	oe->acvp_oe_id = src->acvp_oe_id;

	/* Use a global lock for all OE definitions */
	oe->def_lock = src->def_lock;
	acvp_def_get_lock(oe->def_lock);

out:
	if (ret)
		acvp_def_del_oe(def);
	return ret;
}

static int acvp_def_init(struct definition **def_out, struct def_algo_map *map)
{
	struct definition *def;
	int ret = 0;

	def = calloc(1, sizeof(*def));
	CKNULL(def, -ENOMEM);

	def->algos = map->algos;
	def->num_algos = map->num_algos;

	*def_out = def;

out:
	if (ret && def)
		free(def);
	return ret;
}

static void acvp_def_release(struct definition *def)
{
	if (!def)
		return;

	acvp_def_del_oe(def);
	acvp_def_del_vendor(def);
	acvp_def_del_info(def);
	free(def);
}

void acvp_def_release_all(void)
{
	struct definition *def = NULL;

	mutex_lock(&def_mutex);
	if (!def_head)
		goto out;

	def = def_head;

	while (def) {
		struct definition *curr = def;

		def = def->next;
		acvp_def_release(curr);
	}

	def_head = NULL;

out:
	mutex_unlock(&def_mutex);
	return;
}

static int acvp_def_write_json(struct json_object *config, const char *pathname)
{
	int ret, fd;

	mutex_lock(&def_file_access_mutex);

	fd = open(pathname, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return -errno;

	ret = json_object_to_fd(fd, config, JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE);

	close(fd);

	mutex_unlock(&def_file_access_mutex);

	return ret;
}

static int acvp_def_read_json(struct json_object **config, const char *pathname)
{
	struct json_object *filecontent;
	int ret = 0, fd;

	mutex_reader_lock(&def_file_access_mutex);

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -errno;

	filecontent = json_object_from_fd(fd);

	close(fd);

	CKNULL(filecontent, -EFAULT);
	*config = filecontent;

out:
	mutex_reader_unlock(&def_file_access_mutex);
	return ret;
}

static int acvp_def_set_value(struct json_object *json,
			      const char *name, uint32_t id, bool *set)
{
	struct json_object *val;
	uint32_t tmp;
	int ret;

	ret = json_find_key(json, name, &val, json_type_int);
	if (ret) {
		json_object_object_add(json, name, json_object_new_int(id));
		*set = true;
		return 0;
	}

	tmp = json_object_get_int(val);
	if (tmp >= INT_MAX)
		return -EINVAL;

	if (tmp != id) {
		json_object_set_int(val, id);
		*set = true;
	}

	return 0;
}

struct acvp_def_update_id_entry {
	const char *name;
	uint32_t id;
};

static int acvp_def_update_id(const char *pathname,
			      const struct acvp_def_update_id_entry *list,
			      uint32_t list_entries)
{
	struct json_object *config = NULL;
	unsigned int i;
	int ret = 0;
	bool updated = false;

	CKINT_LOG(acvp_def_read_json(&config, pathname),
		  "Cannot parse config file %s\n", pathname);

	for (i = 0; i < list_entries; i++) {
		/* Do not write a zero ID */
		if (!list[i].name || !list[i].id)
			continue;

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Updating entry %s with %u\n",
		       list[i].name, list[i].id);
		CKINT(acvp_def_set_value(config, list[i].name, list[i].id,
					 &updated));
	}

	if (updated)
		CKINT(acvp_def_write_json(config, pathname));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

#define ACVP_DEF_PRODUCTION_ID(x)					\
	(acvp_req_is_production() ? x "Production" : x)

static void acvp_def_read_vendor_id(struct json_object *vendor_config,
				    struct def_vendor *def_vendor)
{
	/*
	 * No error handling - in case we cannot find entry, it will be
	 * created.
	 */
	json_get_uint(vendor_config, ACVP_DEF_PRODUCTION_ID("acvpVendorId"),
		      &def_vendor->acvp_vendor_id);
	json_get_uint(vendor_config, ACVP_DEF_PRODUCTION_ID("acvpAddressId"),
		      &def_vendor->acvp_addr_id);
}

int acvp_def_get_vendor_id(struct def_vendor *def_vendor)
{
	struct json_object *vendor_config = NULL;
	int ret = 0;

	acvp_def_lock_lock(def_vendor->def_lock);

	CKINT_LOG(acvp_def_read_json(&vendor_config,
				     def_vendor->def_vendor_file),
		  "Cannot parse vendor information config file %s\n",
		  def_vendor->def_vendor_file);

	acvp_def_read_vendor_id(vendor_config, def_vendor);

out:
	if (ret)
		acvp_def_lock_unlock(def_vendor->def_lock);

	ACVP_JSON_PUT_NULL(vendor_config);
	return ret;
}

static int acvp_def_update_vendor_id(struct def_vendor *def_vendor)
{
	struct acvp_def_update_id_entry list[2];

	list[0].name = ACVP_DEF_PRODUCTION_ID("acvpVendorId");
	list[0].id = def_vendor->acvp_vendor_id;
	list[1].name = ACVP_DEF_PRODUCTION_ID("acvpAddressId");
	list[1].id = def_vendor->acvp_addr_id;

	return acvp_def_update_id(def_vendor->def_vendor_file, list, 2);
}

int acvp_def_put_vendor_id(struct def_vendor *def_vendor)
{
	int ret;

	if (!def_vendor)
		return 0;

	CKINT(acvp_def_update_vendor_id(def_vendor));
	acvp_def_lock_unlock(def_vendor->def_lock);

out:
	return ret;
}

static void acvp_def_read_person_id(struct json_object *vendor_config,
				    struct def_vendor *def_vendor)
{
	/*
	 * No error handling - in case we cannot find entry, it will be
	 * created.
	 */

	json_get_uint(vendor_config, ACVP_DEF_PRODUCTION_ID("acvpPersonId"),
		      &def_vendor->acvp_person_id);
}

int acvp_def_get_person_id(struct def_vendor *def_vendor)
{
	struct json_object *vendor_config = NULL;
	int ret = 0;

	acvp_def_lock_lock(def_vendor->def_lock);

	CKINT_LOG(acvp_def_read_json(&vendor_config,
				     def_vendor->def_vendor_file),
		  "Cannot parse vendor information config file %s\n",
		  def_vendor->def_vendor_file);

	/* Person ID depends on vendor ID and thus we read it. */
	acvp_def_read_vendor_id(vendor_config, def_vendor);
	acvp_def_read_person_id(vendor_config, def_vendor);

out:
	if (ret)
		acvp_def_lock_unlock(def_vendor->def_lock);

	ACVP_JSON_PUT_NULL(vendor_config);
	return ret;
}

static int acvp_def_update_person_id(struct def_vendor *def_vendor)
{
	struct acvp_def_update_id_entry list;

	list.name = ACVP_DEF_PRODUCTION_ID("acvpPersonId");
	list.id = def_vendor->acvp_person_id;

	return acvp_def_update_id(def_vendor->def_vendor_file, &list, 1);
}

int acvp_def_put_person_id(struct def_vendor *def_vendor)
{
	int ret;

	if (!def_vendor)
		return 0;

	CKINT(acvp_def_update_person_id(def_vendor));
	acvp_def_lock_unlock(def_vendor->def_lock);

out:
	return ret;
}

static void acvp_def_read_oe_id(struct json_object *oe_config,
			        struct def_oe *def_oe)
{
	/*
	 * No error handling - in case we cannot find entry, it will be
	 * created.
	 */

	json_get_uint(oe_config, ACVP_DEF_PRODUCTION_ID("acvpOeId"),
		      &def_oe->acvp_oe_id);
	json_get_uint(oe_config, ACVP_DEF_PRODUCTION_ID("acvpOeDepProcId"),
		      &def_oe->acvp_oe_dep_proc_id);
	json_get_uint(oe_config, ACVP_DEF_PRODUCTION_ID("acvpOeDepSwId"),
		      &def_oe->acvp_oe_dep_sw_id);
}

int acvp_def_get_oe_id(struct def_oe *def_oe)
{
	struct json_object *oe_config = NULL;
	int ret = 0;

	acvp_def_lock_lock(def_oe->def_lock);

	CKINT_LOG(acvp_def_read_json(&oe_config, def_oe->def_oe_file),
		  "Cannot parse operational environment config file %s\n",
		  def_oe->def_oe_file);

	acvp_def_read_oe_id(oe_config, def_oe);

out:
	if (ret)
		acvp_def_lock_unlock(def_oe->def_lock);

	ACVP_JSON_PUT_NULL(oe_config);
	return ret;
}

static int acvp_def_update_oe_id(struct def_oe *def_oe)
{
	struct acvp_def_update_id_entry list[3];

	list[0].name = ACVP_DEF_PRODUCTION_ID("acvpOeId");
	list[0].id = def_oe->acvp_oe_id;
	list[1].name = ACVP_DEF_PRODUCTION_ID("acvpOeDepProcId");
	list[1].id = def_oe->acvp_oe_dep_proc_id;
	list[2].name = ACVP_DEF_PRODUCTION_ID("acvpOeDepSwId");
	list[2].id = def_oe->acvp_oe_dep_sw_id;

	return acvp_def_update_id(def_oe->def_oe_file, list, 3);
}

int acvp_def_put_oe_id(struct def_oe *def_oe)
{
	int ret;

	if (!def_oe)
		return 0;

	CKINT(acvp_def_update_oe_id(def_oe));
	acvp_def_lock_unlock(def_oe->def_lock);

out:
	return ret;
}

static int acvp_def_find_module_id(struct def_info *def_info,
				   struct json_object *config,
				   struct json_object **entry)
{
	struct json_object *id_list, *id_entry = NULL;
	unsigned int i;
	int ret;
	bool found = false;

	CKINT(json_find_key(config, ACVP_DEF_PRODUCTION_ID("acvpModuleIds"),
			    &id_list, json_type_array));

	for (i = 0; i < json_object_array_length(id_list); i++) {
		const char *str;

		id_entry = json_object_array_get_idx(id_list, i);

		if (!id_entry)
			break;

		CKINT(json_get_string(id_entry,
				      ACVP_DEF_PRODUCTION_ID("acvpModuleName"),
				      &str));
		if (strncmp(def_info->module_name, str,
				strlen(def_info->module_name)))
			continue;

		found = true;
		break;
	}

	if (found) {
		*entry = id_entry;
	} else {
		ret = -ENOENT;
	}

out:
	return ret;
}

static int acvp_def_read_module_id(struct def_info *def_info, uint32_t *id)
{
	struct json_object *config = NULL;
	struct json_object *entry;
	int ret;

	CKINT_LOG(acvp_def_read_json(&config, def_info->def_module_file),
		  "Cannot parse operational environment config file %s\n",
		  def_info->def_module_file);

	CKINT(acvp_def_find_module_id(def_info, config, &entry));
	CKINT(json_get_uint(entry, ACVP_DEF_PRODUCTION_ID("acvpModuleId"), id));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

int acvp_def_get_module_id(struct def_info *def_info)
{
	acvp_def_lock_lock(def_info->def_lock);

	/*
	 * Return code not needed - if entry does not exist,
	 * module id is zero.
	 */
	acvp_def_read_module_id(def_info, &def_info->acvp_module_id);

	/*
	 * As each instantiated module has its own module ID, each
	 * def_info instance manages its own private ID. Hence, we do not
	 * need to keep the lock unlike for the other IDs.
	 */
	acvp_def_lock_unlock(def_info->def_lock);

	return 0;
}

static int acvp_def_update_module_id(struct def_info *def_info)
{
	struct json_object *config = NULL, *id_list, *id_entry;
	int ret = 0;
	bool updated = false;

	if (!def_info->module_name || !def_info->acvp_module_id)
		return 0;

	CKINT_LOG(acvp_def_read_json(&config, def_info->def_module_file),
		  "Cannot parse operational environment config file %s\n",
		  def_info->def_module_file);

	ret = acvp_def_find_module_id(def_info, config, &id_entry);
	if (ret) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "Adding entry %s with %u\n",
			       def_info->module_name,
			       def_info->acvp_module_id);

		ret = json_find_key(config,
				    ACVP_DEF_PRODUCTION_ID("acvpModuleIds"),
				    &id_list, json_type_array);
		if (ret) {
			/*
			 * entire array acvpModuleIds does not exist,
			 * create it
			 */
			id_list = json_object_new_array();
			CKNULL(id_list, -ENOMEM);
			CKINT(json_object_object_add(config,
				ACVP_DEF_PRODUCTION_ID("acvpModuleIds"),
						     id_list));
		}

		id_entry = json_object_new_object();
		CKNULL(id_entry, -ENOMEM);
		CKINT(json_object_array_add(id_list, id_entry));

		CKINT(json_object_object_add(id_entry,
				ACVP_DEF_PRODUCTION_ID("acvpModuleName"),
				json_object_new_string(def_info->module_name)));
		CKINT(json_object_object_add(id_entry,
				ACVP_DEF_PRODUCTION_ID("acvpModuleId"),
				json_object_new_int(def_info->acvp_module_id)));
		updated = true;
	} else {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "Updating entry %s with %u\n",
			       def_info->module_name, def_info->acvp_module_id);
		CKINT(acvp_def_set_value(id_entry,
					 ACVP_DEF_PRODUCTION_ID("acvpModuleId"),
					 def_info->acvp_module_id, &updated));
	}

	if (updated)
		CKINT(acvp_def_write_json(config, def_info->def_module_file));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

int acvp_def_put_module_id(struct def_info *def_info)
{
	int ret;

	if (!def_info)
		return 0;

	acvp_def_lock_lock(def_info->def_lock);
	CKINT(acvp_def_update_module_id(def_info));
	acvp_def_lock_unlock(def_info->def_lock);

out:
	return ret;
}

static int acvp_check_features(uint64_t feature)
{
	unsigned int i;
	uint64_t allowed_features = 0;

	for (i = 0; i < ARRAY_SIZE(acvp_features); i++) {
		allowed_features |= acvp_features[i].feature;
	}

	if (feature > allowed_features)
		return -EINVAL;
	return 0;
}

static int acvp_def_load_config(const char *oe_file, const char *vendor_file,
				const char *info_file, const char *impl_file)
{
	struct json_object *oe_config = NULL, *vendor_config = NULL,
			   *info_config = NULL, *impl_config = NULL,
			   *impl_array = NULL;
	struct def_algo_map *map = NULL;
	struct definition *def = NULL;
	struct def_oe oe;
	struct def_info info;
	struct def_vendor vendor;
	int ret;

	memset(&oe, 0, sizeof(oe));
	memset(&info, 0, sizeof(info));
	memset(&vendor, 0, sizeof(vendor));

	CKNULL_LOG(oe_file, -EINVAL,
		   "No operational environment file name given for definition config\n");
	CKNULL_LOG(vendor_file, -EINVAL,
		   "No vendor file name given for definition config\n");
	CKNULL_LOG(info_file, -EINVAL,
		   "No module information file name given for definition config\n");
	CKNULL_LOG(impl_file, -EINVAL,
		   "No module implementation definition file name given for definition config\n");

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Reading module definitions from %s, %s, %s, %s\n",
	       oe_file, vendor_file, info_file, impl_file);

	CKINT(acvp_def_alloc_lock(&oe.def_lock));
	CKINT_LOG(acvp_def_read_json(&oe_config,oe_file),
		  "Cannot parse operational environment config file %s\n",
		  oe_file);
	CKINT(json_get_string(oe_config, "oeEnvName",
			      (const char **)&oe.oe_env_name));
	CKINT(json_get_string(oe_config, "manufacturer",
			      (const char **)&oe.manufacturer));
	CKINT(json_get_string(oe_config, "procFamily",
			      (const char **)&oe.proc_family));
	CKINT(json_get_string(oe_config, "procName",
			      (const char **)&oe.proc_name));
	CKINT(json_get_string(oe_config, "procSeries",
			      (const char **)&oe.proc_series));
	CKINT(json_get_uint(oe_config, "features", (uint32_t *)&oe.features));
	CKINT(acvp_check_features(oe.features));
	CKINT(json_get_uint(oe_config, "envType", (uint32_t *)&oe.env_type));
	CKINT(acvp_module_oe_type(oe.env_type, NULL));

	/*
	 * No error handling - one or more may not exist.
	 */
	json_get_string(oe_config, "cpe", (const char **)&oe.cpe);
	json_get_string(oe_config, "swid", (const char **)&oe.swid);
	json_get_string(oe_config, "oe_description",
			(const char **)&oe.oe_description);
	if (!oe.cpe && !oe.swid) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "CPE or SWID missing\n");
		ret = -EINVAL;
		goto out;
	}

	/* We do not read the OE / dependencies IDs here */

	/* Unconstify harmless, because data will be duplicated */
	oe.def_oe_file = (char *)oe_file;

	CKINT(acvp_def_alloc_lock(&info.def_lock));
	CKINT_LOG(acvp_def_read_json(&info_config, info_file),
		  "Cannot parse module information config file %s\n",
		  info_file);
	CKINT(json_get_string(info_config, "moduleName",
			      (const char **)&info.module_name));
	CKINT(json_get_string(info_config, "moduleVersion",
			      (const char **)&info.module_version));
	CKINT(json_get_string(info_config, "moduleDescription",
			      (const char **)&info.module_description));
	CKINT(json_get_uint(info_config, "moduleType",
			    (uint32_t *)&info.module_type));
	CKINT(acvp_module_oe_type(info.module_type, NULL));

	/* We do not read the module ID here */

	/* Unconstify harmless, because data will be duplicated */
	info.def_module_file = (char *)info_file;

	CKINT(acvp_def_alloc_lock(&vendor.def_lock));
	CKINT_LOG(acvp_def_read_json(&vendor_config, vendor_file),
		  "Cannot parse vendor information config file %s\n",
		  vendor_file);
	CKINT(json_get_string(vendor_config, "vendorName",
			      (const char **)&vendor.vendor_name));
	CKINT(json_get_string(vendor_config, "vendorUrl",
			      (const char **)&vendor.vendor_url));
	CKINT(json_get_string(vendor_config, "contactName",
			      (const char **)&vendor.contact_name));
	CKINT(json_get_string(vendor_config, "contactEmail",
			      (const char **)&vendor.contact_email));
	CKINT(json_get_string(vendor_config, "contactPhone",
			      (const char **)&vendor.contact_phone));
	CKINT(json_get_string(vendor_config, "addressStreet",
			      (const char **)&vendor.addr_street));
	CKINT(json_get_string(vendor_config, "addressCity",
			      (const char **)&vendor.addr_locality));
	CKINT(json_get_string(vendor_config, "addressState",
			      (const char **)&vendor.addr_region));
	CKINT(json_get_string(vendor_config, "addressCountry",
			      (const char **)&vendor.addr_country));
	CKINT(json_get_string(vendor_config, "addressZip",
			      (const char **)&vendor.addr_zipcode));

	/* We do not read the vendor and person IDs here */

	/* Unconstify harmless, because data will be duplicated */
	vendor.def_vendor_file = (char *)vendor_file;

	CKINT_LOG(acvp_def_read_json(&impl_config, impl_file),
		  "Cannot parse cipher implementations config file %s\n",
		  impl_file);
	CKINT(json_find_key(impl_config, "implementations",
			    &impl_array, json_type_array));

	mutex_lock(&def_uninstantiated_mutex);

	for (map = def_uninstantiated_head; map != NULL; map = map->next) {
		unsigned int i, found = 0;

		/* Ensure that configuration applies to map. */
		if (strncmp(map->algo_name, info.module_name,
			     strlen(map->algo_name)) ||
		    strncmp(map->processor, oe.proc_family,
			     strlen(map->processor)))
			continue;

		/*
		 * Match one of the requested implementation
		 * configurations.
		 */
		for (i = 0;
		     i < (uint32_t)json_object_array_length(impl_array);
		     i++) {
			struct json_object *impl =
				json_object_array_get_idx(impl_array, i);
			const char *string;

			CKNULL(impl, EINVAL);

			string = json_object_get_string(impl);

			if (!strncmp(map->impl_name, string,
				     strlen(map->impl_name))) {
				found = 1;
				break;
			}
		}

		/* If no entry found, try the next map. */
		if (!found)
			continue;

		/* Instantiate mapping into definition. */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Algorithm map for name %s, processor %s found\n",
		       info.module_name, oe.proc_family);
		ret = acvp_def_init(&def, map);
		if (ret)
			goto unlock;

		ret = acvp_def_add_oe(def, &oe);
		if (ret)
			goto unlock;

		ret = acvp_def_add_vendor(def, &vendor);
		if (ret)
			goto unlock;

		ret = acvp_def_add_info(def, &info, map->impl_name);
		if (ret)
			goto unlock;

		acvp_register_def(def);
	}

unlock:
	mutex_unlock(&def_uninstantiated_mutex);
out:
	ACVP_JSON_PUT_NULL(oe_config);
	ACVP_JSON_PUT_NULL(vendor_config);
	ACVP_JSON_PUT_NULL(info_config);
	ACVP_JSON_PUT_NULL(impl_config);

	/*
	 * In error case, acvp_def_release will free the lock, in successful
	 * case we need to check if the lock is used at all and free it if not.
	 */
	if (ret) {
		acvp_def_release(def);
	} else {
		acvp_def_dealloc_unused_lock(oe.def_lock);
		acvp_def_dealloc_unused_lock(vendor.def_lock);
		acvp_def_dealloc_unused_lock(info.def_lock);
	}
	return ret;
}

/* Sanity check for path name. */
static int acvp_def_usable_dirent(struct dirent *dirent)
{
	size_t filenamelen, extensionlen;
	int ret = 0;

	/* Check that entry is neither ".", "..", or a hidden file */
	if (!strncmp(dirent->d_name, ".", 1))
		goto out;

	/* Check that it is a regular file or a symlink */
	if (dirent->d_type != DT_REG && dirent->d_type != DT_LNK)
		goto out;

	filenamelen = strlen(dirent->d_name);
	extensionlen = strlen(ACVP_DEF_CONFIG_FILE_EXTENSION);

	/* Check that file name is long enough */
	if (filenamelen < extensionlen + 1)
		goto out;

	/* Check for presence of extension */
	if (strncmp(dirent->d_name + filenamelen - extensionlen,
		    ACVP_DEF_CONFIG_FILE_EXTENSION, extensionlen))
		goto out;

	ret = 1;

out:
	if (!ret)
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Skipping directory entry %s\n", dirent->d_name);

	return ret;
}

DSO_PUBLIC
int acvp_def_config(const char *directory)
{
	struct dirent *oe_dirent, *vendor_dirent, *info_dirent, *impl_dirent;
	DIR *oe_dir = NULL, *vendor_dir = NULL, *info_dir = NULL,
	    *impl_dir = NULL;
	char oe_pathname[FILENAME_MAX - 257],
	     vendor_pathname[FILENAME_MAX - 257],
	     info_pathname[FILENAME_MAX - 257],
	     impl_pathname[FILENAME_MAX  - 257];
	char oe[FILENAME_MAX], vendor[FILENAME_MAX], info[FILENAME_MAX],
	     impl[FILENAME_MAX];
	int ret = 0;

	CKNULL_LOG(directory, -EINVAL, "Configuration directory missing\n");

	snprintf(oe_pathname, sizeof(oe_pathname) - 256, "%s/%s", directory,
		 ACVP_DEF_DIR_OE);
	oe_dir = opendir(oe_pathname);
	CKNULL_LOG(oe_dir, -errno, "Failed to open directory %s\n",
		   oe_pathname);

	snprintf(vendor_pathname, sizeof(vendor_pathname) - 256, "%s/%s",
		 directory, ACVP_DEF_DIR_VENDOR);
	vendor_dir = opendir(vendor_pathname);
	CKNULL_LOG(vendor_dir, -errno, "Failed to open directory %s\n",
		   vendor_pathname);

	snprintf(info_pathname, sizeof(info_pathname) - 256, "%s/%s", directory,
		 ACVP_DEF_DIR_MODINFO);
	info_dir = opendir(info_pathname);
	CKNULL_LOG(info_dir, -errno, "Failed to open directory %s\n",
		   info_pathname);

	snprintf(impl_pathname, sizeof(impl_pathname) - 256, "%s/%s", directory,
		 ACVP_DEF_DIR_IMPLEMENTATIONS);
	impl_dir = opendir(impl_pathname);
	CKNULL_LOG(impl_dir, -errno, "Failed to open directory %s\n",
		   impl_pathname);

	/* Process all permutations of configuration files. */
	while ((vendor_dirent = readdir(vendor_dir)) != NULL) {
		if (!acvp_def_usable_dirent(vendor_dirent))
			continue;

		snprintf(vendor, sizeof(vendor), "%s/%s", vendor_pathname,
			 vendor_dirent->d_name);

		while ((info_dirent = readdir(info_dir)) != NULL) {
			if (!acvp_def_usable_dirent(info_dirent))
				continue;

			snprintf(info, sizeof(info), "%s/%s", info_pathname,
				 info_dirent->d_name);

			while ((oe_dirent = readdir(oe_dir)) != NULL) {
				if (!acvp_def_usable_dirent(oe_dirent))
					continue;

				snprintf(oe, sizeof(oe), "%s/%s", oe_pathname,
					 oe_dirent->d_name);

				while ((impl_dirent = readdir(impl_dir)) != NULL) {
					if (!acvp_def_usable_dirent(impl_dirent))
						continue;

					snprintf(impl, sizeof(impl), "%s/%s",
						 impl_pathname,
						 impl_dirent->d_name);
					CKINT(acvp_def_load_config(oe, vendor,
								   info, impl));
				}
				rewinddir(impl_dir);
			}
			rewinddir(oe_dir);
		}
		rewinddir(info_dir);
	}

out:
	if (oe_dir)
		closedir(oe_dir);
	if (vendor_dir)
		closedir(vendor_dir);
	if (info_dir)
		closedir(info_dir);
	if (impl_dir)
		closedir(impl_dir);
	return ret;
}

DSO_PUBLIC
int acvp_def_default_config(const char *config_basedir)
{
	struct dirent *dirent;
	DIR *dir = NULL;
	char configdir[255];
	char pathname[FILENAME_MAX];
	int ret = 0;

	if (config_basedir) {
		snprintf(configdir, sizeof(configdir), "%s", config_basedir);
	} else {
		snprintf(configdir, sizeof(configdir), "%s",
			 ACVP_DEF_DEFAULT_CONFIG_DIR);
	}
	dir = opendir(configdir);
	CKNULL_LOG(dir, -errno, "Failed to open directory %s\n",
		   ACVP_DEF_DEFAULT_CONFIG_DIR);

	while ((dirent = readdir(dir)) != NULL) {
		/* Check that entry is neither ".", "..", or a hidden file */
		if (!strncmp(dirent->d_name, ".", 1))
			continue;

		/* Check that it is a directory */
		if (dirent->d_type != DT_DIR)
			continue;

		snprintf(pathname, sizeof(pathname), "%s/%s",
			 configdir, dirent->d_name);

		CKINT(acvp_def_config(pathname));
	}

out:
	if (dir)
		closedir(dir);
	return ret;
}

void acvp_register_algo_map(struct def_algo_map *curr_map, unsigned int nrmaps)
{
	struct def_algo_map *tmp_map;
	unsigned int i;

	if (!curr_map || !nrmaps) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Programming error: missing map definitions\n");
		return;
	}

	/* Safety-measure to prevent programming bugs to affect us. */
	curr_map[nrmaps - 1].next = NULL;

	/* Link all provided maps together */
	for (i = 0; i < (nrmaps - 1); i++)
		curr_map[i].next = &curr_map[i + 1];

	mutex_lock(&def_uninstantiated_mutex);

	/* There was no previously registered map, take the first spot. */
	if (!def_uninstantiated_head) {
		def_uninstantiated_head = curr_map;
		goto out;
	}

	/* Find the last entry to append the current map. */
	for (tmp_map = def_uninstantiated_head;
	     tmp_map != NULL;
	     tmp_map = tmp_map->next) {
		/* do not re-register */
		if (curr_map == tmp_map)
			goto out;

		if (!tmp_map->next) {
			tmp_map->next = curr_map;
			goto out;
		}
	}

out:
	mutex_unlock(&def_uninstantiated_mutex);
	return;
}
