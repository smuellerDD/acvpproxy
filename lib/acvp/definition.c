/* ACVP definition handling
 *
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
#include "request_helper.h"

/* List of instantiated module definitions */
static DEFINE_MUTEX_UNLOCKED(def_mutex);
static struct definition *def_head = NULL;

/* List of uninstantiated module definitions */
static DEFINE_MUTEX_UNLOCKED(def_uninstantiated_mutex);
static struct def_algo_map *def_uninstantiated_head = NULL;

static DEFINE_MUTEX_UNLOCKED(def_file_access_mutex);

/*****************************************************************************
 * Conversions
 *****************************************************************************/

struct def_dependency_type_names {
	enum def_dependency_type type;
	const char *name;
};

static struct def_dependency_type_names type_name[] = {
	{ def_dependency_os, "os" },
	{ def_dependency_os, "Operating System" },
	{ def_dependency_hardware, "processor" },
	{ def_dependency_hardware, "cpu" },
	{ def_dependency_software, "software" },
	{ def_dependency_firmware, "firmware" }
};

int acvp_dep_type2name(enum def_dependency_type type, const char **name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(type_name); i++) {
		if (type == type_name[i].type) {
			*name = type_name[i].name;
			return 0;
		}
	}

	return -ENOENT;
}

int acvp_dep_name2type(const char *name, enum def_dependency_type *type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(type_name); i++) {
		size_t len = strlen(type_name[i].name);

		if (strlen(name) == len &&
		    !strncmp(name, type_name[i].name, len)) {
			*type = type_name[i].type;
			return 0;
		}
	}

	return -ENOENT;
}

/*****************************************************************************
 * Handle refcnt lock
 *****************************************************************************/
int acvp_def_alloc_lock(struct def_lock **lock)
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

static int acvp_match_def_search(const struct acvp_search_ctx *search,
				 const struct definition *def)
{
	const struct def_vendor *vendor = def->vendor;
	const struct def_info *mod_info = def->info;
	const struct def_oe *oe = def->oe;
	const struct def_dependency *def_dep;
	bool match = false, match_found = false, match2 = false,
	     match2_found = false;

	if (!acvp_find_match(search->modulename, mod_info->module_name,
			     search->modulename_fuzzy_search) ||
	    !acvp_find_match(search->moduleversion, mod_info->module_version,
			     search->moduleversion_fuzzy_search) ||
	    !acvp_find_match(search->orig_modulename,
			     mod_info->orig_module_name, false) ||
	    !acvp_find_match(search->vendorname, vendor->vendor_name,
			     search->vendorname_fuzzy_search))
		return -ENOENT;

	for (def_dep = oe->def_dep; def_dep != NULL; def_dep = def_dep->next) {
		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			match |= acvp_find_match(search->execenv, def_dep->name,
						 search->execenv_fuzzy_search);
			match_found = true;
			break;
		case def_dependency_hardware:
			match2 |=
				acvp_find_match(search->processor,
						def_dep->proc_name,
						search->processor_fuzzy_search);
			match2_found = true;
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			return -ENOENT;
		}
	}

	/*
	 * If we do not have a specific dependency type, we match it
	 * trivially.
	 */
	if (!match_found)
		match = true;
	if (!match2_found)
		match2 = true;

	/* It is permissible to have no dependencies at all */
	if (oe->def_dep && (!match || !match2))
		return -ENOENT;

	return 0;
}

const struct definition *acvp_find_def(const struct acvp_search_ctx *search,
				       const struct definition *processed_ptr)
{
	const struct definition *tmp_def = NULL;

	mutex_reader_lock(&def_mutex);

	if (processed_ptr) {
		/*
		 * Guarantee that the pointer is valid as we unlock the mutex
		 * when returning.
		 */
		for (tmp_def = def_head; tmp_def != NULL;
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

	for (; tmp_def != NULL; tmp_def = tmp_def->next) {
		int ret = acvp_match_def_search(search, tmp_def);

		if (ret == -ENOENT)
			continue;
		else if (ret) {
			tmp_def = NULL;
			goto out;
		}

		if (search->with_es_def && !tmp_def->es)
			continue;

		break;
	}

out:
	mutex_reader_unlock(&def_mutex);
	return tmp_def;
}

static inline struct json_object *
acvp_export_string_to_json(const char *str)
{
	return str ? json_object_new_string(str) : NULL;
}

static int acvp_export_def_search_dep_v1(const struct def_oe *oe,
					 struct json_object *s)
{
	const struct def_dependency *def_dep;
	int ret = 0;
	bool execenv_done = false, cpu_done = false;

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name && !execenv_done) {
			CKINT(json_object_object_add(
				s, "execenv",
				acvp_export_string_to_json(def_dep->name)));
			/* we only store one */
			execenv_done = true;
		}

		if (def_dep->proc_name && def_dep->proc_family &&
		    def_dep->proc_series && !cpu_done) {
			CKINT(json_object_object_add(
				s, "processor",
				acvp_export_string_to_json(def_dep->proc_name)));
			CKINT(json_object_object_add(
				s, "processorFamily",
				acvp_export_string_to_json(def_dep->proc_family)));
			CKINT(json_object_object_add(
				s, "processorSeries",
				acvp_export_string_to_json(def_dep->proc_series)));
			cpu_done = true;
		}

		if (execenv_done && cpu_done)
			break;
	}

out:
	return ret;
}

static int acvp_export_def_search_dep_v2(const struct def_oe *oe,
					 struct json_object *s)
{
	const struct def_dependency *def_dep;
	struct json_object *array;
	int ret;

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(s, "dependencies", array));

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		struct json_object *entry = json_object_new_object();

		CKNULL(entry, -ENOMEM);
		CKINT(json_object_array_add(array, entry));

		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			CKINT(json_object_object_add(
				entry, "execenv",
				acvp_export_string_to_json(def_dep->name)));
			break;
		case def_dependency_hardware:
			CKINT(json_object_object_add(
				entry, "processor",
				acvp_export_string_to_json(def_dep->proc_name)));
			CKINT(json_object_object_add(
				entry, "processorFamily",
				acvp_export_string_to_json(def_dep->proc_family)));
			CKINT(json_object_object_add(
				entry, "processorSeries",
				acvp_export_string_to_json(def_dep->proc_series)));
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown dependency type\n");
			ret = -EINVAL;
			goto out;
		}
	}

out:
	return ret;
}

int acvp_export_def_search(const struct acvp_testid_ctx *testid_ctx)
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

	CKINT(json_object_object_add(
		s, "moduleName",
		acvp_export_string_to_json(mod_info->module_name)));
	CKINT(json_object_object_add(
		s, "moduleVersion",
		acvp_export_string_to_json(mod_info->module_version)));
	CKINT(json_object_object_add(
		s, "vendorName",
		acvp_export_string_to_json(vendor->vendor_name)));

	switch (oe->config_file_version) {
	case 0:
	case 1:
		CKINT(acvp_export_def_search_dep_v1(oe, s));
		break;
	case 2:
		CKINT(acvp_export_def_search_dep_v2(oe, s));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown dependency version\n");
		ret = -EINVAL;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	str = json_object_to_json_string_ext(
		s, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(str, -EFAULT, "JSON object conversion into string failed\n");

	/* Write the JSON data to disk */
	tmp.buf = (uint8_t *)str;
	tmp.len = (uint32_t)strlen(str);
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, ACVP_DS_DEF_REFERENCE,
					      false, &tmp));

out:
	ACVP_JSON_PUT_NULL(s);
	return ret;
}

static int acvp_match_def_v1(const struct acvp_testid_ctx *testid_ctx,
			     const struct json_object *def_config)
{
	const struct definition *def = testid_ctx->def;
	struct acvp_search_ctx search;
	int ret;

	memset(&search, 0, sizeof(search));
	CKINT(json_get_string(def_config, "moduleName",
			      (const char **)&search.modulename));
	json_get_string(def_config, "moduleVersion",
			(const char **)&search.moduleversion);
	CKINT(json_get_string(def_config, "vendorName",
			      (const char **)&search.vendorname));
	ret = json_get_string(def_config, "execenv",
			      (const char **)&search.execenv);
	if (ret < 0)
		search.execenv = NULL;
	CKINT(json_get_string(def_config, "processor",
			      (const char **)&search.processor));

	ret = acvp_match_def_search(&search, def);
	if (ret) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search does not match with old search\n",
		       testid_ctx->testid);
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search matches with old search\n",
		       testid_ctx->testid);
	}

out:
	return ret;
}

static int acvp_match_def_v2(const struct acvp_testid_ctx *testid_ctx,
			     const struct json_object *def_config)
{
	const struct definition *def = testid_ctx->def;
	struct acvp_search_ctx search;
	struct json_object *dep_array;
	unsigned int i;
	int ret;

	CKINT(json_find_key(def_config, "dependencies", &dep_array,
			    json_type_array));

	memset(&search, 0, sizeof(search));
	CKINT(json_get_string(def_config, "moduleName",
			      (const char **)&search.modulename));
	json_get_string(def_config, "moduleVersion",
			(const char **)&search.moduleversion);
	CKINT(json_get_string(def_config, "vendorName",
			      (const char **)&search.vendorname));
	CKINT(acvp_match_def_search(&search, def));

	for (i = 0; i < json_object_array_length(dep_array); i++) {
		struct json_object *dep_entry =
			json_object_array_get_idx(dep_array, i);

		memset(&search, 0, sizeof(search));
		CKNULL(dep_array, -EFAULT);

		/*
		 * no error checks, as we do not require these entries to be
		 * found everywhere
		 */
		json_get_string(dep_entry, "execenv",
				(const char **)&search.execenv);
		json_get_string(dep_entry, "processor",
				(const char **)&search.processor);
		CKINT(acvp_match_def_search(&search, def));
	}

out:
	if (ret) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search does not match with old search\n",
		       testid_ctx->testid);
	} else {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Crypto definition for testID %u for current search matches with old search\n",
		       testid_ctx->testid);
	}
	return ret;
}

int acvp_match_def(const struct acvp_testid_ctx *testid_ctx,
		   const struct json_object *def_config)
{
	struct json_object *o;

	if (json_find_key(def_config, "dependencies", &o, json_type_array))
		return acvp_match_def_v1(testid_ctx, def_config);

	return acvp_match_def_v2(testid_ctx, def_config);
}

DSO_PUBLIC
int acvp_list_unregistered_definitions(void)
{
	struct def_algo_map *map = NULL;

	fprintf(stderr, "Algo Name | Processor | Implementation Name\n");

	mutex_reader_lock(&def_uninstantiated_mutex);

	for (map = def_uninstantiated_head; map != NULL; map = map->next)
		fprintf(stderr, "%s | %s | %s\n", map->algo_name,
			map->processor, map->impl_name);

	mutex_reader_unlock(&def_uninstantiated_mutex);

	fprintf(stderr,
		"\nUse this information to create instantiations by module definition configuration files\n");

	return 0;
}

static void acvp_get_max(int *len, const char *str)
{
	int tmp = str ? (int)strlen(str) : 0;

	if (tmp > *len)
		*len = tmp;
}

DSO_PUBLIC
int acvp_list_registered_definitions(const struct acvp_search_ctx *search)
{
	const struct definition *def;
	unsigned int vsid = 0;
	int v_len = 11, o_len = 2, p_len = 4, m_len = 11, mv_len = 7;
	char bottomline[200];

	/* Finding maximum sizes */
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
		const struct def_dependency *def_dep = oe->def_dep;

		acvp_get_max(&v_len, vendor->vendor_name);
		acvp_get_max(&m_len, mod_info->module_name);
		acvp_get_max(&mv_len, mod_info->module_version);

		for (; def_dep; def_dep = def_dep->next) {
			acvp_get_max(&o_len, def_dep->name);
			acvp_get_max(&p_len, def_dep->proc_name);
		}

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

	/* Printing data */
	fprintf(stderr, "%*s | %*s | %*s | %*s | %*s | %5s\n", v_len,
		"Vendor Name", o_len, "OE", p_len, "Proc", m_len, "Module Name",
		mv_len, "Version", "vsIDs");

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
		const struct def_dependency *def_dep;
		bool found = false;

		//%*s | %*s | %*s | %*s | %5u\n",
		fprintf(stderr, "%*s |", v_len, vendor->vendor_name);

		for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
			if (def_dep->name) {
				if (found)
					fprintf(stderr, " +");
				fprintf(stderr, " %*s", o_len, def_dep->name);
				found = true;
			}
		}

		if (found)
			fprintf(stderr, " | ");
		else
			fprintf(stderr, " %*s |", o_len, "");

		found = false;
		for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
			if (def_dep->proc_name) {
				if (found)
					fprintf(stderr, " + ");
				fprintf(stderr, "%*s", p_len,
					def_dep->proc_name);
				found = true;
			}
		}

		if (found)
			fprintf(stderr, " | ");
		else
			fprintf(stderr, "%*s | ", p_len, "");

		fprintf(stderr, "%*s | %*s | %5u\n", m_len,
			mod_info->module_name, mv_len, mod_info->module_version,
			def->num_algos);

		vsid += def->num_algos;

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

	v_len += o_len + p_len + m_len + mv_len + 15 + 5;
	if (v_len < 0)
		v_len = 20;
	if (v_len > (int)sizeof(bottomline))
		v_len = sizeof(bottomline) - 1;
	memset(bottomline, 61, (unsigned long)v_len);
	bottomline[v_len] = '\0';
	fprintf(stderr, "%s\n", bottomline);
	fprintf(stderr,
		"Expected numbers of vsIDs for listed definitions: %u\n", vsid);

	return 0;
}

void acvp_def_free_info(struct def_info *info)
{
	ACVP_PTR_FREE_NULL(info->module_name);
	ACVP_PTR_FREE_NULL(info->impl_name);
	ACVP_PTR_FREE_NULL(info->impl_description);
	ACVP_PTR_FREE_NULL(info->orig_module_name);
	ACVP_PTR_FREE_NULL(info->module_name_filesafe);
	ACVP_PTR_FREE_NULL(info->module_name_internal);
	ACVP_PTR_FREE_NULL(info->module_version);
	ACVP_PTR_FREE_NULL(info->module_version_filesafe);
	ACVP_PTR_FREE_NULL(info->module_description);
	ACVP_PTR_FREE_NULL(info->def_module_file);
	acvp_def_put_lock(info->def_lock);
}

static void acvp_def_del_info(struct definition *def)
{
	struct def_info *info;

	if (!def || !def->info)
		return;

	info = def->info;

	acvp_def_free_info(info);
	ACVP_PTR_FREE_NULL(def->info);
}

void acvp_def_free_vendor(struct def_vendor *vendor)
{
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
}

static void acvp_def_del_vendor(struct definition *def)
{
	struct def_vendor *vendor;

	if (!def || !def->vendor)
		return;

	vendor = def->vendor;

	acvp_def_free_vendor(vendor);
	ACVP_PTR_FREE_NULL(def->vendor);
}

static void acvp_def_free_dep(struct def_oe *oe)
{
	struct def_dependency *def_dep;

	if (!oe)
		return;

	def_dep = oe->def_dep;

	while (def_dep) {
		struct def_dependency *tmp = def_dep;

		ACVP_PTR_FREE_NULL(def_dep->name);
		ACVP_PTR_FREE_NULL(def_dep->cpe);
		ACVP_PTR_FREE_NULL(def_dep->swid);
		ACVP_PTR_FREE_NULL(def_dep->description);
		ACVP_PTR_FREE_NULL(def_dep->manufacturer);
		ACVP_PTR_FREE_NULL(def_dep->proc_family);
		ACVP_PTR_FREE_NULL(def_dep->proc_family_internal);
		ACVP_PTR_FREE_NULL(def_dep->proc_name);
		ACVP_PTR_FREE_NULL(def_dep->proc_series);

		def_dep = def_dep->next;
		free(tmp);
	}
}

void acvp_def_free_oe(struct def_oe *oe)
{
	if (!oe)
		return;

	acvp_def_free_dep(oe);
	ACVP_PTR_FREE_NULL(oe->def_oe_file);
	acvp_def_put_lock(oe->def_lock);
}

static void acvp_def_del_oe(struct definition *def)
{
	struct def_oe *oe;

	if (!def || !def->oe)
		return;

	oe = def->oe;

	acvp_def_free_oe(oe);
	ACVP_PTR_FREE_NULL(def->oe);
}

static void acvp_def_del_deps(struct definition *def)
{
	struct def_deps *deps;

	if (!def || !def->deps)
		return;

	deps = def->deps;

	while (deps) {
		struct def_deps *tmp = deps->next;

		ACVP_PTR_FREE_NULL(deps->dep_cipher);
		ACVP_PTR_FREE_NULL(deps->dep_name);
		ACVP_PTR_FREE_NULL(deps);

		/*
		 * deps->dependency is freed by the deallocation of the
		 * definition.
		 */

		deps = tmp;
	}
}

int acvp_def_module_name(char **newname, const char *module_name,
			 const char *impl_name)
{
	char *tmp;
	int ret = 0;

	if (impl_name) {
		size_t len = strlen(module_name) + strlen(impl_name) + 4;

		tmp = malloc(len);
		CKNULL(tmp, -ENOMEM);
		snprintf(tmp, len, "%s (%s)", module_name, impl_name);
	} else {
		tmp = strdup(module_name);
		CKNULL(tmp, -ENOMEM);
	}

	*newname = tmp;

out:
	if (ret)
		free(tmp);

	return ret;
}

static int acvp_def_add_info(struct definition *def, const struct def_info *src,
			     const char *impl_name,
			     const char *impl_description)
{
	struct def_info *info;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");

	info = calloc(1, sizeof(*info));
	CKNULL(info, -ENOMEM);
	def->info = info;

	CKINT(acvp_def_module_name(&info->module_name, src->module_name,
				   impl_name));
	CKINT(acvp_duplicate(&info->impl_name, impl_name));
	CKINT(acvp_duplicate(&info->impl_description, impl_description));
	CKINT(acvp_duplicate(&info->orig_module_name, src->module_name));
	CKINT(acvp_duplicate(&info->module_name_filesafe, info->module_name));
	CKINT(acvp_sanitize_string(info->module_name_filesafe));
	CKINT(acvp_duplicate(&info->module_name_internal,
			     info->module_name_internal));

	CKINT(acvp_duplicate(&info->module_version, src->module_version));
	CKINT(acvp_duplicate(&info->module_version_filesafe,
			     info->module_version));
	CKINT(acvp_sanitize_string(info->module_version_filesafe));

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

static int acvp_def_add_vendor(struct definition *def,
			       const struct def_vendor *src)
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

static int acvp_def_add_dep(struct def_oe *oe, const struct def_dependency *src)
{
	struct def_dependency *def_dep;
	int ret;

	CKNULL_LOG(oe, -EINVAL, "Definition context missing\n");

	def_dep = calloc(1, sizeof(*def_dep));
	CKNULL(def_dep, -ENOMEM);

	/* Append to the end */
	if (!oe->def_dep) {
		oe->def_dep = def_dep;
	} else {
		struct def_dependency *tmp;

		for (tmp = oe->def_dep; tmp; tmp = tmp->next) {
			if (!tmp->next) {
				tmp->next = def_dep;
				break;
			}
		}
	}

	CKINT(acvp_duplicate(&def_dep->name, src->name));
	CKINT(acvp_duplicate(&def_dep->cpe, src->cpe));
	CKINT(acvp_duplicate(&def_dep->swid, src->swid));
	CKINT(acvp_duplicate(&def_dep->description, src->description));
	CKINT(acvp_duplicate(&def_dep->manufacturer, src->manufacturer));
	CKINT(acvp_duplicate(&def_dep->proc_family, src->proc_family));
	CKINT(acvp_duplicate(&def_dep->proc_family_internal,
			     src->proc_family_internal));
	CKINT(acvp_duplicate(&def_dep->proc_name, src->proc_name));
	CKINT(acvp_duplicate(&def_dep->proc_series, src->proc_series));
	def_dep->features = src->features;

	def_dep->acvp_dep_id = src->acvp_dep_id;
	def_dep->def_dependency_type = src->def_dependency_type;

out:
	return ret;
}

static int acvp_def_add_oe(struct definition *def, const struct def_oe *src)
{
	struct def_oe *oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");

	oe = calloc(1, sizeof(*oe));
	CKNULL(oe, -ENOMEM);
	def->oe = oe;

	CKINT(acvp_duplicate(&oe->def_oe_file, src->def_oe_file));
	oe->acvp_oe_id = src->acvp_oe_id;
	oe->config_file_version = src->config_file_version;

	for (def_dep = src->def_dep; def_dep; def_dep = def_dep->next) {
		CKINT(acvp_def_add_dep(oe, def_dep));
	}

	/* Use a global lock for all OE definitions */
	oe->def_lock = src->def_lock;
	acvp_def_get_lock(oe->def_lock);

out:
	if (ret)
		acvp_def_del_oe(def);
	return ret;
}

static int acvp_def_add_deps(struct definition *def,
			     const struct json_object *json_deps,
			     const enum acvp_deps_type dep_type)
{
	const struct def_info *info;
	struct def_deps *deps;
	struct json_object *my_dep;
	struct json_object_iter one_dep;
	int ret;

	CKNULL_LOG(def, -EINVAL, "Definition context missing\n");
	if (!json_deps) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "No dependency definition found\n");
		ret = 0;
		goto out;
	}

	deps = def->deps;
	info = def->info;
	CKNULL_LOG(info, -EINVAL, "Module meta data missing\n");
	CKNULL(info->impl_name, 0);

	/* Try finding the dependency for our definition */
	ret = json_find_key(json_deps, info->impl_name, &my_dep,
			    json_type_object);
	if (ret) {
		/* Not found, skipping further processing */
		ret = 0;
		goto out;
	}

	/* Iterate over the one or more entries found in the configuration */
	json_object_object_foreachC(my_dep, one_dep)
	{
		/* Allocate a linked-list entry for the definition */
		if (deps) {
			/* fast-forward to the end */
			while (deps->next)
				deps = deps->next;

			deps->next = calloc(1, sizeof(*deps));
			CKNULL(deps->next, -ENOMEM);
			deps = deps->next;
		} else {
			/* First entry */
			deps = calloc(1, sizeof(*deps));
			CKNULL(deps, -ENOMEM);
			def->deps = deps;
		}

		/*
		 * The key is the cipher name for which the dependency is
		 * used.
		 */
		CKINT(acvp_duplicate(&deps->dep_cipher, one_dep.key));
		/*
		 * The value is the pointer to the impl_name fulfilling the
		 * dependency.
		 */
		CKINT(acvp_duplicate(&deps->dep_name,
				     json_object_get_string(one_dep.val)));

		/* Store the type of the defintion */
		deps->deps_type = dep_type;

		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Initiate dependency for %s: type %s -> %s\n",
		       info->impl_name, deps->dep_cipher, deps->dep_name);
	}

out:
	return ret;
}

/*
 * Fill in the def_deps->dependency pointers
 *
 * The code iterates through the dependency linked list and tries to find
 * the definition matching the impl_name defined by the dependency. If a
 * match is found, the pointer to the definition is added to the dependency
 * for later immediate resolution.
 */
static int acvp_def_wire_deps(void)
{
	struct definition *curr_def;
	int ret = 0;

	mutex_lock(&def_mutex);
	if (!def_head)
		goto out;

	/* Iterate through the linked list of the registered definitions. */
	for (curr_def = def_head; curr_def != NULL; curr_def = curr_def->next) {
		const struct def_vendor *vendor;
		const struct def_oe *oe;
		const struct def_info *curr_info;
		const struct def_dependency *def_dep;
		struct def_deps *deps;
		struct acvp_search_ctx search;

		if (!curr_def->deps)
			continue;

		vendor = curr_def->vendor;
		oe = curr_def->oe;
		curr_info = curr_def->info;

		/* Make sure that the dependency definition has the same OE. */
		memset(&search, 0, sizeof(search));
		search.orig_modulename = curr_info->orig_module_name;
		search.moduleversion = curr_info->module_version;
		search.vendorname = vendor->vendor_name;

		for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
			if (def_dep->name) {
				search.execenv = def_dep->name;
				break;
			}
		}

		for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
			if (def_dep->proc_name) {
				search.processor = def_dep->proc_name;
				break;
			}
		}

		/* Iterate through the dependencies */
		for (deps = curr_def->deps; deps != NULL; deps = deps->next) {
			struct definition *s_def;

			/*
			 * We have an external certificate reference. The user
			 * requested a manual dependency handling for this
			 * entry, we do not resolve anything.
			 */
			if (deps->deps_type == acvp_deps_manual_resolution)
				continue;

			/*
			 * Search through all definitions for a match of the
			 * impl_name.
			 */
			for (s_def = def_head; s_def != NULL;
			     s_def = s_def->next) {
				struct def_info *info = s_def->info;

				CKNULL(info, -EFAULT);

				/*
				 * We allow a fuzzy search. The reason is that
				 * a dependency can be matched by any
				 * implementation as long as it is tested.
				 * For example, if we have a Hash DRBG which
				 * depends on SHA, it does not matter whether
				 * the dependency is covered by a SHA C
				 * implementation or by a SHA assembler
				 */
				if (!acvp_find_match(deps->dep_name,
						     info->impl_name, true))
					continue;

				/* We do not allow references to ourselves */
				if (s_def == curr_def)
					continue;

				/*
				 * Make sure that the dependency applies to our
				 * environment.
				 */
				if (acvp_match_def_search(&search, s_def))
					continue;

				/* We found a match, wire it up */
				deps->dependency = s_def;
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Found dependency for %s: type %s -> %s (vendor name: %s, OE %s, processor %s)\n",
				       curr_info->impl_name, deps->dep_cipher,
				       info->impl_name, search.vendorname,
				       search.execenv, search.processor);

				/*
				 * One match is sufficient. As we have a fuzzy
				 * search criteria above, we may find multiple
				 * matches.
				 */
				break;
			}

			/*
			 * If we did not find anything, the references are
			 * wrong
			 */
			CKNULL_LOG(
				deps->dependency, -EINVAL,
				"Unmatched dependency for %s: type %s -> %s (vendor name: %s, OE %s, processor %s)\n",
				curr_info->impl_name, deps->dep_cipher,
				deps->dep_name, search.vendorname,
				search.execenv, search.processor);
		}
	}

out:
	mutex_unlock(&def_mutex);
	return ret;
}

static int acvp_def_init(struct definition **def_out,
			 const struct def_algo_map *map)
{
	struct definition *def;
	int ret = 0;

	def = calloc(1, sizeof(*def));
	CKNULL(def, -ENOMEM);

	if (map) {
		def->algos = map->algos;
		def->num_algos = map->num_algos;
	}

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
	acvp_def_del_deps(def);
	esvp_def_es_free(def->es);
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

	ret = json_object_to_fd(fd, config,
				JSON_C_TO_STRING_PRETTY |
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

static int acvp_def_set_value(struct json_object *json, const char *name,
			      const uint32_t id, bool *set)
{
	struct json_object *val;
	uint32_t tmp;
	int ret;

	ret = json_find_key(json, name, &val, json_type_int);
	if (ret) {
		/* No addition of entry if it was rejected */
		if (id & ACVP_REQUEST_REJECTED)
			return 0;

		json_object_object_add(json, name,
				       json_object_new_int((int)id));
		*set = true;
		return 0;
	}

	/* Delete entry */
	if (id & ACVP_REQUEST_REJECTED) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Removing ID entry for %s\n", name);
		json_object_object_del(json, name);
		return 0;
	}

	tmp = (uint32_t)json_object_get_int(val);
	if (tmp >= INT_MAX)
		return -EINVAL;

	if (tmp != id) {
		json_object_set_int(val, (int)id);
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
			      const uint32_t list_entries)
{
	struct json_object *config = NULL;
	unsigned int i;
	int ret = 0;
	bool updated = false;

	CKNULL(pathname, -EINVAL);

	CKINT_LOG(acvp_def_read_json(&config, pathname),
		  "Cannot parse config file %s\n", pathname);

	for (i = 0; i < list_entries; i++) {
		if (!list[i].name)
			continue;

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Updating entry %s with %u\n", list[i].name, list[i].id);
		CKINT(acvp_def_set_value(config, list[i].name, list[i].id,
					 &updated));
	}

	if (updated)
		CKINT(acvp_def_write_json(config, pathname));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

static int acvp_def_set_str(struct json_object *json, const char *name,
			    const char *str, bool *set)
{
	struct json_object *val;
	int ret;

	if (!name)
		return -EINVAL;

	/* We may have a string or NULL */
	ret = json_find_key(json, name, &val, json_type_string);
	if (ret)
		ret = json_find_key(json, name, &val, json_type_null);

	/* Create a new entry */
	if (ret) {
		/* Do not create a NULL entry */
		if (!str)
			return 0;

		json_object_object_add(json, name, json_object_new_string(str));
		*set = true;
		return 0;
	}

	/* Update existing entry to NULL */
	if (!str) {
		/* We do not need updating as the entry is already NULL */
		if (json_object_is_type(val, json_type_null))
			return 0;

		json_object_object_del(json, name);
		json_object_object_add(json, name, NULL);
		*set = true;
		return 0;
	}

	/* Update existing entry if it does not match */
	if (!acvp_find_match(str, json_object_get_string(val), false)) {
		json_object_set_string(val, str);
		*set = true;
	}

	return 0;
}

struct acvp_def_update_string_entry {
	const char *name;
	const char *str;
};

static int acvp_def_update_str(const char *pathname,
			       const struct acvp_def_update_string_entry *list,
			       const uint32_t list_entries)
{
	struct json_object *config = NULL;
	unsigned int i;
	int ret = 0;
	bool updated = false;

	CKNULL(pathname, -EINVAL);

	CKINT_LOG(acvp_def_read_json(&config, pathname),
		  "Cannot parse config file %s\n", pathname);

	for (i = 0; i < list_entries; i++) {
		if (!list[i].name)
			continue;

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Updating entry %s with %s\n", list[i].name,
		       list[i].str);
		CKINT(acvp_def_set_str(config, list[i].name, list[i].str,
				       &updated));
	}

	if (updated)
		CKINT(acvp_def_write_json(config, pathname));

out:
	return ret;
}

static void acvp_def_read_vendor_id(const struct json_object *vendor_config,
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

static int acvp_def_update_vendor_id(const struct def_vendor *def_vendor)
{
	struct acvp_def_update_id_entry list[2];

	list[0].name = ACVP_DEF_PRODUCTION_ID("acvpVendorId");
	list[0].id = def_vendor->acvp_vendor_id;
	list[1].name = ACVP_DEF_PRODUCTION_ID("acvpAddressId");
	list[1].id = def_vendor->acvp_addr_id;

	return acvp_def_update_id(def_vendor->def_vendor_file, list, 2);
}

int acvp_def_put_vendor_id(const struct def_vendor *def_vendor)
{
	int ret;

	if (!def_vendor)
		return 0;

	CKINT(acvp_def_update_vendor_id(def_vendor));
	acvp_def_lock_unlock(def_vendor->def_lock);

out:
	return ret;
}

static void acvp_def_read_person_id(const struct json_object *vendor_config,
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

static int acvp_def_update_person_id(const struct def_vendor *def_vendor)
{
	struct acvp_def_update_id_entry list;

	list.name = ACVP_DEF_PRODUCTION_ID("acvpPersonId");
	list.id = def_vendor->acvp_person_id;

	return acvp_def_update_id(def_vendor->def_vendor_file, &list, 1);
}

int acvp_def_put_person_id(const struct def_vendor *def_vendor)
{
	int ret;

	if (!def_vendor)
		return 0;

	CKINT(acvp_def_update_person_id(def_vendor));
	acvp_def_lock_unlock(def_vendor->def_lock);

out:
	return ret;
}

static void acvp_def_read_oe_id_v1(const struct json_object *oe_config,
				   struct def_oe *def_oe)
{
	struct def_dependency *def_dep;

	json_get_uint(oe_config, ACVP_DEF_PRODUCTION_ID("acvpOeId"),
		      &def_oe->acvp_oe_id);

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			json_get_uint(oe_config,
				      ACVP_DEF_PRODUCTION_ID("acvpOeDepSwId"),
				      &def_dep->acvp_dep_id);
			break;
		case def_dependency_hardware:
			json_get_uint(oe_config,
				      ACVP_DEF_PRODUCTION_ID("acvpOeDepProcId"),
				      &def_dep->acvp_dep_id);
			break;

		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			return;
		}
	}
}

static int acvp_def_oe_config_get_deps(const struct def_oe *def_oe,
				       const struct json_object *config,
				       struct json_object **dep_array_out)
{
	struct json_object *dep_array;
	struct def_dependency *def_dep;
	unsigned int i = 0;
	int ret;

	CKINT(json_find_key(config, "oeDependencies", &dep_array,
			    json_type_array));

	/*
	 * The following loop implicitly assumes that the order of the entries
	 * in the in-memory linked list are identical to the order of the
	 * entries in the JSON array found in the configuration file.
	 */
	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next)
		i++;

	if (i != json_object_array_length(dep_array)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "JSON configuration file %s inconsistent with in-memory representation of the file read during startup\n",
		       def_oe->def_oe_file);
		ret = -EFAULT;
		goto out;
	}

	*dep_array_out = dep_array;

out:
	return ret;
}

static void acvp_def_read_oe_id_v2(struct json_object *oe_config,
				   struct def_oe *def_oe)
{
	struct json_object *dep_array;
	struct def_dependency *def_dep;
	unsigned int i = 0;

	if (acvp_def_oe_config_get_deps(def_oe, oe_config, &dep_array))
		return;

	json_get_uint(oe_config, ACVP_DEF_PRODUCTION_ID("acvpId"),
		      &def_oe->acvp_oe_id);

	/*
	 * Iterate over configuration file dependency array and in-memory
	 * dependency definition in unison.
	 */
	for (def_dep = def_oe->def_dep, i = 0;
	     def_dep && (i < json_object_array_length(dep_array));
	     def_dep = def_dep->next, i++) {
		struct json_object *dep_entry =
			json_object_array_get_idx(dep_array, i);

		if (!dep_entry)
			continue;

		json_get_uint(dep_entry, ACVP_DEF_PRODUCTION_ID("acvpId"),
			      &def_dep->acvp_dep_id);
	}
}

int acvp_def_get_oe_id(struct def_oe *def_oe)
{
	struct json_object *oe_config = NULL;
	int ret = 0;

	if (!def_oe)
		return 0;

	acvp_def_lock_lock(def_oe->def_lock);

	CKINT_LOG(acvp_def_read_json(&oe_config, def_oe->def_oe_file),
		  "Cannot parse operational environment config file %s\n",
		  def_oe->def_oe_file);

	/*
	 * No error handling - in case we cannot find entry, it will be
	 * created.
	 */
	switch (def_oe->config_file_version) {
	case 0:
	case 1:
		acvp_def_read_oe_id_v1(oe_config, def_oe);
		break;
	case 2:
		acvp_def_read_oe_id_v2(oe_config, def_oe);
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE configuration file version %u\n",
		       def_oe->config_file_version);
		ret = -EFAULT;
		goto out;
	}

out:
	if (ret)
		acvp_def_lock_unlock(def_oe->def_lock);

	ACVP_JSON_PUT_NULL(oe_config);
	return ret;
}

static int acvp_def_update_oe_id_v1(const struct def_oe *def_oe)
{
	struct acvp_def_update_id_entry list[3];
	struct def_dependency *def_dep;

	list[0].name = ACVP_DEF_PRODUCTION_ID("acvpOeId");
	list[0].id = def_oe->acvp_oe_id;
	list[1].name = ACVP_DEF_PRODUCTION_ID("acvpOeDepProcId");
	list[1].id = 0;
	list[2].name = ACVP_DEF_PRODUCTION_ID("acvpOeDepSwId");
	list[2].id = 0;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			list[2].id = def_dep->acvp_dep_id;
			break;
		case def_dependency_hardware:
			list[1].id = def_dep->acvp_dep_id;
			break;

		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			return -EFAULT;
		}
	}

	return acvp_def_update_id(def_oe->def_oe_file, list, 3);
}

static int acvp_def_update_oe_id_v2(const struct def_oe *def_oe)
{
	struct json_object *config = NULL, *dep_array;
	struct def_dependency *def_dep;
	unsigned int i = 0;
	int ret = 0;
	bool updated = false;

	CKINT_LOG(acvp_def_read_json(&config, def_oe->def_oe_file),
		  "Cannot parse config file %s\n", def_oe->def_oe_file);

	CKINT(acvp_def_oe_config_get_deps(def_oe, config, &dep_array));

	CKINT(acvp_def_set_value(config, ACVP_DEF_PRODUCTION_ID("acvpId"),
				 def_oe->acvp_oe_id, &updated));

	/*
	 * Iterate over configuration file dependency array and in-memory
	 * dependency definition in unison.
	 */
	for (def_dep = def_oe->def_dep, i = 0;
	     def_dep && (i < json_object_array_length(dep_array));
	     def_dep = def_dep->next, i++) {
		struct json_object *dep_entry =
			json_object_array_get_idx(dep_array, i);

		CKNULL(dep_entry, -EINVAL);

		CKINT(acvp_def_set_value(dep_entry,
					 ACVP_DEF_PRODUCTION_ID("acvpId"),
					 def_dep->acvp_dep_id, &updated));
	}

	if (updated)
		CKINT(acvp_def_write_json(config, def_oe->def_oe_file));

out:
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

int acvp_def_put_oe_id(const struct def_oe *def_oe)
{
	int ret;

	if (!def_oe)
		return 0;

	switch (def_oe->config_file_version) {
	case 0:
	case 1:
		CKINT(acvp_def_update_oe_id_v1(def_oe));
		break;
	case 2:
		CKINT(acvp_def_update_oe_id_v2(def_oe));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE configuration file version %u\n",
		       def_oe->config_file_version);
		ret = -EFAULT;
		goto out;
	}
	acvp_def_lock_unlock(def_oe->def_lock);

out:
	return ret;
}

static int acvp_def_update_oe_config_v1(const struct def_oe *def_oe)
{
	struct acvp_def_update_string_entry str_list[7];
	struct def_dependency *def_dep;
	int ret;

	str_list[0].name = "oeEnvName";
	str_list[0].str = NULL;
	str_list[1].name = "cpe";
	str_list[1].str = NULL;
	str_list[2].name = "swid";
	str_list[2].str = NULL;
	str_list[3].name = "manufacturer";
	str_list[3].str = NULL;
	str_list[4].name = "procFamily";
	str_list[4].str = NULL;
	str_list[5].name = "procName";
	str_list[5].str = NULL;
	str_list[6].name = "procSeries";
	str_list[6].str = NULL;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			str_list[0].str = def_dep->name;
			str_list[1].str = def_dep->cpe;
			str_list[2].str = def_dep->swid;
			break;
		case def_dependency_hardware:
			str_list[3].str = def_dep->manufacturer;
			str_list[4].str = def_dep->proc_family;
			str_list[5].str = def_dep->proc_name;
			str_list[6].str = def_dep->proc_series;
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			return -EFAULT;
		}
	}

	acvp_def_lock_lock(def_oe->def_lock);
	ret = acvp_def_update_str(def_oe->def_oe_file, str_list,
				  ARRAY_SIZE(str_list));
	acvp_def_lock_unlock(def_oe->def_lock);

	return ret;
}

static int acvp_def_update_oe_config_v2(const struct def_oe *def_oe)
{
	struct json_object *config = NULL, *dep_array;
	struct def_dependency *def_dep;
	unsigned int i = 0;
	int ret = 0;
	bool updated = false;

	acvp_def_lock_lock(def_oe->def_lock);

	CKINT_LOG(acvp_def_read_json(&config, def_oe->def_oe_file),
		  "Cannot parse config file %s\n", def_oe->def_oe_file);

	CKINT(acvp_def_oe_config_get_deps(def_oe, config, &dep_array));

	/*
	 * Iterate over configuration file dependency array and in-memory
	 * dependency definition in unison.
	 */
	for (def_dep = def_oe->def_dep, i = 0;
	     def_dep && (i < json_object_array_length(dep_array));
	     def_dep = def_dep->next, i++) {
		struct json_object *dep_entry =
			json_object_array_get_idx(dep_array, i);

		CKNULL(dep_entry, -EINVAL);

		switch (def_dep->def_dependency_type) {
		case def_dependency_firmware:
		case def_dependency_os:
		case def_dependency_software:
			CKINT(acvp_def_set_str(dep_entry, "oeEnvName",
					       def_dep->name, &updated));
			CKINT(acvp_def_set_str(dep_entry, "cpe", def_dep->cpe,
					       &updated));
			CKINT(acvp_def_set_str(dep_entry, "swid", def_dep->swid,
					       &updated));
			break;
		case def_dependency_hardware:
			CKINT(acvp_def_set_str(dep_entry, "manufacturer",
					       def_dep->manufacturer,
					       &updated));
			CKINT(acvp_def_set_str(dep_entry, "procFamily",
					       def_dep->proc_family, &updated));
			CKINT(acvp_def_set_str(dep_entry, "procName",
					       def_dep->proc_name, &updated));
			CKINT(acvp_def_set_str(dep_entry, "procSeries",
					       def_dep->proc_series, &updated));
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown OE dependency type\n");
			ret = -EFAULT;
			goto out;
		}
	}

	if (updated)
		CKINT(acvp_def_write_json(config, def_oe->def_oe_file));

out:
	acvp_def_lock_unlock(def_oe->def_lock);
	ACVP_JSON_PUT_NULL(config);
	return ret;
}

int acvp_def_update_oe_config(const struct def_oe *def_oe)
{
	int ret;

	if (!def_oe)
		return 0;

	switch (def_oe->config_file_version) {
	case 0:
	case 1:
		CKINT(acvp_def_update_oe_config_v1(def_oe));
		break;
	case 2:
		CKINT(acvp_def_update_oe_config_v2(def_oe));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown OE configuration file version %u\n",
		       def_oe->config_file_version);
		ret = -EFAULT;
		goto out;
	}

out:
	return ret;
}

static int acvp_def_find_module_id(const struct def_info *def_info,
				   const struct json_object *config,
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

static int acvp_def_read_module_id(const struct def_info *def_info,
				   uint32_t *id)
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

static int acvp_def_update_module_id(const struct def_info *def_info)
{
	struct json_object *config = NULL, *id_list, *id_entry;
	int ret = 0;
	bool updated = false;

	if (!def_info->module_name)
		return 0;

	CKINT_LOG(acvp_def_read_json(&config, def_info->def_module_file),
		  "Cannot parse operational environment config file %s\n",
		  def_info->def_module_file);

	ret = acvp_def_find_module_id(def_info, config, &id_entry);
	if (ret) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Adding entry %s with %u\n", def_info->module_name,
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
			CKINT(json_object_object_add(
				config, ACVP_DEF_PRODUCTION_ID("acvpModuleIds"),
				id_list));
		}

		id_entry = json_object_new_object();
		CKNULL(id_entry, -ENOMEM);
		CKINT(json_object_array_add(id_list, id_entry));

		CKINT(json_object_object_add(
			id_entry, ACVP_DEF_PRODUCTION_ID("acvpModuleName"),
			json_object_new_string(def_info->module_name)));
		CKINT(json_object_object_add(
			id_entry, ACVP_DEF_PRODUCTION_ID("acvpModuleId"),
			json_object_new_int((int)def_info->acvp_module_id)));
		updated = true;
	} else {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Updating entry %s with %u\n", def_info->module_name,
		       def_info->acvp_module_id);
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

int acvp_def_update_module_config(const struct def_info *def_info)
{
	struct acvp_def_update_string_entry str_list[2];
	int ret;

	str_list[0].name = "moduleName";
	str_list[0].str = def_info->orig_module_name;
	str_list[1].name = "moduleVersion";
	str_list[1].str = def_info->module_version;

	acvp_def_lock_lock(def_info->def_lock);
	ret = acvp_def_update_str(def_info->def_module_file, str_list,
				  ARRAY_SIZE(str_list));
	acvp_def_lock_unlock(def_info->def_lock);

	return ret;
}

static int acvp_check_features(const uint64_t feature)
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

static int acvp_def_load_deps(const struct json_object *config,
			      struct definition *def)
{
	struct json_object *deps_int = NULL, *deps_ext = NULL;
	int ret;

	/* Dependencies may not be defined */
	json_find_key(config, "dependencies-internal", &deps_int,
		      json_type_object);
	json_find_key(config, "dependencies-external", &deps_ext,
		      json_type_object);

	/* First stage of dependencies */
	CKINT(acvp_def_add_deps(def, deps_int, acvp_deps_automated_resolution));
	CKINT(acvp_def_add_deps(def, deps_ext, acvp_deps_manual_resolution));

out:
	return ret;
}

static int acvp_def_load_config_dep_typed(const struct json_object *dep_entry,
					  struct def_dependency *def_dep,
					  const char **local_proc_family)
{
	int ret;

	CKNULL(dep_entry, -EINVAL);

	switch (def_dep->def_dependency_type) {
	case def_dependency_firmware:
	case def_dependency_os:
	case def_dependency_software:
		ret = json_get_string_zero_to_null(dep_entry, "oeEnvName",
						(const char **)&def_dep->name);
		if (ret < 0) {
			struct json_object *o = NULL;

			CKINT(json_find_key(dep_entry, "oeEnvName", &o,
					    json_type_null));
			def_dep->name = NULL;
		}
		/*
		* No error handling - one or more may not exist.
		*/
		json_get_string_zero_to_null(dep_entry, "cpe",
					     (const char **)&def_dep->cpe);
		json_get_string_zero_to_null(dep_entry, "swid",
					     (const char **)&def_dep->swid);
		json_get_string_zero_to_null(dep_entry, "oe_description",
					(const char **)&def_dep->description);
		break;
	case def_dependency_hardware:
		CKINT(json_get_string_zero_to_null(dep_entry, "manufacturer",
					(const char **)&def_dep->manufacturer));
		CKINT(json_get_string_zero_to_null(dep_entry, "procFamily",
					(const char **)&def_dep->proc_family));
		/* This is an option */
		json_get_string_zero_to_null(dep_entry, "procFamilyInternal",
				(const char **)&def_dep->proc_family_internal);
		CKINT(json_get_string_zero_to_null(dep_entry, "procName",
					(const char **)&def_dep->proc_name));
		json_get_string_zero_to_null(dep_entry, "procSeries",
					(const char **)&def_dep->proc_series);
		CKINT(json_get_uint(dep_entry, "features",
				    (uint32_t *)&def_dep->features));
		CKINT(acvp_check_features(def_dep->features));
		*local_proc_family = def_dep->proc_family_internal ?
						   def_dep->proc_family_internal :
						   def_dep->proc_family;
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

static int acvp_def_load_config_dep(struct json_object *dep_entry,
				    struct def_dependency *def_dep,
				    const char **local_proc_family)
{
	const char *str;
	int ret;

	CKNULL(dep_entry, -EINVAL);

	CKINT(json_get_string(dep_entry, "dependencyType", &str));
	CKINT_LOG(acvp_dep_name2type(str, &def_dep->def_dependency_type),
		  "dependencyType %s is unknown\n", str);
	CKINT(acvp_def_load_config_dep_typed(dep_entry, def_dep,
					     local_proc_family));

out:
	return ret;
}

static int acvp_def_load_config_oe(const struct json_object *oe_config,
				   struct def_oe *oe,
				   const char **local_proc_family)
{
	struct def_dependency def_dep;
	struct json_object *dep_array;
	uint32_t type;
	int ret;

	CKINT(acvp_def_alloc_lock(&oe->def_lock));

	/* Check whether we have old or new style configuration file */
	ret = json_find_key(oe_config, "oeDependencies", &dep_array,
			    json_type_array);

	if (!ret) {
		/* We have version 2 configuration file */
		struct json_object *oe_name;
		unsigned int i;

		/*
		 * Sanity check: if any of the following entries are found,
		 * the user has a mix-n-match of v1 and v2 config files.
		 */
		if (!json_find_key(oe_config, "oeEnvName", &oe_name,
				   json_type_string) ||
		    !json_find_key(oe_config, "oeEnvName", &oe_name,
				   json_type_null) ||
		    !json_find_key(oe_config, "manufacturer", &oe_name,
				   json_type_string))
			goto v2_err;

		oe->config_file_version = 2;

		for (i = 0; i < json_object_array_length(dep_array); i++) {
			struct json_object *dep_entry =
				json_object_array_get_idx(dep_array, i);

			memset(&def_dep, 0, sizeof(def_dep));

			CKINT_LOG(
				acvp_def_load_config_dep(dep_entry, &def_dep,
							 local_proc_family),
				"Loading of dependency configuration %u failed\n",
				i);
			CKINT(acvp_def_add_dep(oe, &def_dep));
		}

		goto out;
	}

	/* We have version 1 configuration file */
	memset(&def_dep, 0, sizeof(def_dep));

	/* Software dependency */
	oe->config_file_version = 1;
	def_dep.def_dependency_type = def_dependency_software;
	CKINT(acvp_def_load_config_dep_typed(oe_config, &def_dep,
					     local_proc_family));
	ret = json_get_uint(oe_config, "envType", &type);
	/* Kludge for the old handling */
	if (!ret && (type == 2))
		def_dep.def_dependency_type = def_dependency_firmware;
	CKINT(acvp_def_add_dep(oe, &def_dep));

	/* Processor dependency */
	memset(&def_dep, 0, sizeof(def_dep));
	def_dep.def_dependency_type = def_dependency_hardware;
	CKINT(acvp_def_load_config_dep_typed(oe_config, &def_dep,
					     local_proc_family));
	CKINT(acvp_def_add_dep(oe, &def_dep));

	/* We do not read the dependency ID here */

#if 0
	if (!oe.cpe && !oe.swid) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "CPE or SWID missing\n");
		ret = -EINVAL;
		goto out;
	}
#endif

	/* We do not read the OE and dependency ID here */

out:
	return ret;

v2_err:
	logger(LOGGER_ERR, LOGGER_C_ANY,
	       "Mix-n-match of v1 and v2 style OE configuration not permissible\n");
	ret = -EINVAL;
	goto out;
}

static int acvp_def_load_config_module(const struct json_object *info_config,
				       struct def_info *info,
				       const char **local_module_name)
{
	int ret;

	CKINT(acvp_def_alloc_lock(&info->def_lock));
	CKINT(json_get_string_zero_to_null(info_config, "moduleName",
					   (const char **)&info->module_name));
	/* This is an option */
	json_get_string_zero_to_null(info_config, "moduleNameInternal",
				(const char **)&info->module_name_internal);
	CKINT(json_get_string_zero_to_null(info_config, "moduleVersion",
				(const char **)&info->module_version));
	CKINT(json_get_string_zero_to_null(info_config, "moduleDescription",
				(const char **)&info->module_description));
	ret = json_get_uint(info_config, "moduleType",
			    (uint32_t *)&info->module_type);
	if (ret < 0) {
		const char *str;
		CKINT(json_get_string(info_config, "moduleType", &str));
		CKINT(acvp_module_type_name_to_enum(str, &info->module_type));
	}
	CKINT(acvp_module_oe_type(info->module_type, NULL));

	/* Shall we use the internal name for the mapping lookup? */
	*local_module_name = info->module_name_internal ?
					   info->module_name_internal :
					   info->module_name;

	/* We do not read the module ID here */

out:
	return ret;
}

static int acvp_def_load_config_vendor(const struct json_object *vendor_config,
				       struct def_vendor *vendor)
{
	int ret;

	CKINT(acvp_def_alloc_lock(&vendor->def_lock));
	CKINT(json_get_string_zero_to_null(vendor_config, "vendorName",
					(const char **)&vendor->vendor_name));
	CKINT(json_get_string_zero_to_null(vendor_config, "vendorUrl",
					(const char **)&vendor->vendor_url));
	CKINT(json_get_string_zero_to_null(vendor_config, "contactName",
					(const char **)&vendor->contact_name));
	CKINT(json_get_string_zero_to_null(vendor_config, "contactEmail",
					(const char **)&vendor->contact_email));
	/* no error handling */
	json_get_string_zero_to_null(vendor_config, "contactPhone",
					(const char **)&vendor->contact_phone);
	CKINT(json_get_string_zero_to_null(vendor_config, "addressStreet",
					(const char **)&vendor->addr_street));
	CKINT(json_get_string_zero_to_null(vendor_config, "addressCity",
					(const char **)&vendor->addr_locality));
	ret = json_get_string_zero_to_null(vendor_config, "addressState",
					(const char **)&vendor->addr_region);
	if (ret)
		vendor->addr_region = NULL;
	CKINT(json_get_string_zero_to_null(vendor_config, "addressCountry",
					(const char **)&vendor->addr_country));
	CKINT(json_get_string_zero_to_null(vendor_config, "addressZip",
					(const char **)&vendor->addr_zipcode));

	/* We do not read the vendor and person IDs here */

out:
	return ret;
}

static int acvp_def_load_config(const char *basedir, const char *oe_file,
				const char *vendor_file, const char *info_file,
				const char *impl_file)
{
	struct json_object *oe_config = NULL, *vendor_config = NULL,
			   *info_config = NULL, *impl_config = NULL,
			   *impl_array = NULL;
	struct def_algo_map *map = NULL;
	struct definition *def = NULL;
	struct def_oe oe;
	struct def_info info;
	struct def_vendor vendor;

	const char *local_module_name, *local_proc_family = NULL;
	int ret;
	bool registered = false;

	memset(&oe, 0, sizeof(oe));
	memset(&info, 0, sizeof(info));
	memset(&vendor, 0, sizeof(vendor));

	CKNULL_LOG(
		oe_file, -EINVAL,
		"No operational environment file name given for definition config\n");
	CKNULL_LOG(vendor_file, -EINVAL,
		   "No vendor file name given for definition config\n");
	CKNULL_LOG(
		info_file, -EINVAL,
		"No module information file name given for definition config\n");
	/* It is permissible to have a NULL impl_file */

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Reading module definitions from %s, %s, %s, %s\n", oe_file,
	       vendor_file, info_file, impl_file ? impl_file :
				"Implementation definition not provided");

	/* Load OE configuration */
	CKINT_LOG(acvp_def_read_json(&oe_config, oe_file),
		  "Cannot parse operational environment config file %s\n",
		  oe_file);
	CKINT_LOG(acvp_def_load_config_oe(oe_config, &oe, &local_proc_family),
		  "Loading of OE configuration file %s failed\n", oe_file);
	if (!local_proc_family)
		local_proc_family = "unknown processor family";
	/* Unconstify harmless, because data will be duplicated */
	oe.def_oe_file = (char *)oe_file;

	/* Load module configuration */
	CKINT_LOG(acvp_def_read_json(&info_config, info_file),
		  "Cannot parse module information config file %s\n",
		  info_file);
	CKINT_LOG(acvp_def_load_config_module(info_config, &info,
					      &local_module_name),
		  "Loading of module configuration file %s failed\n",
		  info_file);
	/* Unconstify harmless, because data will be duplicated */
	info.def_module_file = (char *)info_file;

	/* Load vendor configuration */
	CKINT_LOG(acvp_def_read_json(&vendor_config, vendor_file),
		  "Cannot parse vendor information config file %s\n",
		  vendor_file);
	CKINT_LOG(acvp_def_load_config_vendor(vendor_config, &vendor),
		  "Loading of vendor configuration file %s failed\n",
		  vendor_file);
	/* Unconstify harmless, because data will be duplicated */
	vendor.def_vendor_file = (char *)vendor_file;

	/* Allow an empty impl file, for example when we simply sync-meta */
	if (impl_file) {
		CKINT_LOG(acvp_def_read_json(&impl_config, impl_file),
			  "Cannot parse cipher implementations config file %s\n",
			  impl_file);
		CKINT(json_find_key(impl_config, "implementations", &impl_array,
				    json_type_array));
	}

	mutex_lock(&def_uninstantiated_mutex);

	for (map = def_uninstantiated_head; map != NULL; map = map->next) {
		size_t i, found = 0;

		if (!impl_array)
			break;

		/* Ensure that configuration applies to map. */
		if (strncmp(map->algo_name, local_module_name,
			    strlen(map->algo_name)) ||
		    strncmp(map->processor, local_proc_family,
			    strlen(map->processor)))
			continue;

		/*
		 * Match one of the requested implementation
		 * configurations.
		 */
		for (i = 0; i < json_object_array_length(impl_array); i++) {
			struct json_object *impl =
				json_object_array_get_idx(impl_array, i);
			const char *string;

			/*
			 * If this loop executes, we have some registered
			 * module definition eventually. Note, the registered
			 * false setting is used for ESVP only where there is
			 * no ACVP definition, but ESVP definition.
			 */
			registered = true;

			CKNULL(impl, EINVAL);

			string = json_object_get_string(impl);

			if (acvp_find_match(map->impl_name, string, false)) {
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
		       info.module_name, local_proc_family);
		CKINT_ULCK(acvp_def_init(&def, map));
		CKINT_ULCK(acvp_def_add_oe(def, &oe));
		CKINT_ULCK(acvp_def_add_vendor(def, &vendor));
		CKINT_ULCK(acvp_def_add_info(def, &info, map->impl_name,
					     map->impl_description));
		CKINT_ULCK(esvp_def_config(basedir, &def->es));

		/* First stage of dependencies */
		CKINT_ULCK(acvp_def_load_deps(impl_config, def));
		CKINT_ULCK(acvp_def_load_deps(oe_config, def));
		CKINT_ULCK(acvp_def_load_deps(vendor_config, def));
		CKINT_ULCK(acvp_def_load_deps(info_config, def));

		def->uninstantiated_def = map;

		acvp_register_def(def);

		registered = true;
	}

	if (!registered) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Register %s without cipher definition\n",
		       info.module_name);
		CKINT_ULCK(acvp_def_init(&def, NULL));
		CKINT_ULCK(acvp_def_add_oe(def, &oe));
		CKINT_ULCK(acvp_def_add_vendor(def, &vendor));
		CKINT_ULCK(acvp_def_add_info(def, &info, NULL, NULL));
		CKINT_ULCK(esvp_def_config(basedir, &def->es));

		/* First stage of dependencies */
		CKINT_ULCK(acvp_def_load_deps(impl_config, def));
		CKINT_ULCK(acvp_def_load_deps(oe_config, def));
		CKINT_ULCK(acvp_def_load_deps(vendor_config, def));
		CKINT_ULCK(acvp_def_load_deps(info_config, def));

		acvp_register_def(def);
	}

unlock:
	mutex_unlock(&def_uninstantiated_mutex);
out:
	ACVP_JSON_PUT_NULL(oe_config);
	ACVP_JSON_PUT_NULL(vendor_config);
	ACVP_JSON_PUT_NULL(info_config);
	ACVP_JSON_PUT_NULL(impl_config);
	acvp_def_free_dep(&oe);

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

static int acvp_def_usable_dirent(const struct dirent *dirent)
{
	return acvp_usable_dirent(dirent, ACVP_DEF_CONFIG_FILE_EXTENSION);
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
		impl_pathname[FILENAME_MAX - 257];
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
	/* we allow implementation to be non-existant */
	if (!impl_dir) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No implementation directory found - only meta data synchronization possible!\n");
	}

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
				bool impl_found = false;

				if (!acvp_def_usable_dirent(oe_dirent))
					continue;

				snprintf(oe, sizeof(oe), "%s/%s", oe_pathname,
					 oe_dirent->d_name);

				if (!impl_dir) {
					CKINT(acvp_def_load_config(directory,
								   oe, vendor,
								   info, NULL));
					continue;
				}

				while ((impl_dirent = readdir(impl_dir)) !=
				       NULL) {
					if (!acvp_def_usable_dirent(
						    impl_dirent))
						continue;

					impl_found = true;

					snprintf(impl, sizeof(impl), "%s/%s",
						 impl_pathname,
						 impl_dirent->d_name);
					CKINT(acvp_def_load_config(directory,
								   oe, vendor,
								   info, impl));
				}

				if (!impl_found) {
					CKINT(acvp_def_load_config(directory,
								   oe, vendor,
								   info, NULL));
				}

				rewinddir(impl_dir);
			}
			rewinddir(oe_dir);
		}
		rewinddir(info_dir);
	}

	/*
	 * Resolving the dependencies at this point implies that the
	 * dependency resolution is confined to an IUT. For example, if OpenSSL
	 * has multiple cipher implementations defined, all of these
	 * implementations are used for resolving the dependencies. But, say,
	 * a reference to the Linux kernel API IUT will not be resolved.
	 *
	 * This is due to the fact that our current function only operates
	 * on one given module definition directory.
	 */
	CKINT(acvp_def_wire_deps());

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
	int ret = 0, errsv;

	if (config_basedir) {
		snprintf(configdir, sizeof(configdir), "%s", config_basedir);
	} else {
		snprintf(configdir, sizeof(configdir), "%s",
			 ACVP_DEF_DEFAULT_CONFIG_DIR);
	}

	dir = opendir(configdir);
	errsv = errno;

	if (!dir && errsv == ENOENT) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Configuration directory %s not present, skipping\n",
		       configdir);
		goto out;
	}

	CKNULL_LOG(dir, -errsv, "Failed to open directory %s\n",
		   ACVP_DEF_DEFAULT_CONFIG_DIR);

	while ((dirent = readdir(dir)) != NULL) {
		/* Check that entry is neither ".", "..", or a hidden file */
		if (!strncmp(dirent->d_name, ".", 1))
			continue;

		/* Check that it is a directory */
		if (dirent->d_type != DT_DIR)
			continue;

		snprintf(pathname, sizeof(pathname), "%s/%s", configdir,
			 dirent->d_name);

		CKINT(acvp_def_config(pathname));
	}

out:
	if (dir)
		closedir(dir);
	return ret;
}

void acvp_register_algo_map(struct def_algo_map *curr_map,
			    const unsigned int nrmaps)
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
	for (tmp_map = def_uninstantiated_head; tmp_map != NULL;
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
