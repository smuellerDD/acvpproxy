/* List all pending request IDs
 *
 * Copyright (C) 2019 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "definition.h"
#include "internal.h"

enum acvp_list_types {
	acvp_list_type_unknown,
	acvp_list_type_certificate,
	acvp_list_type_vendor,
	acvp_list_type_address,
	acvp_list_type_person,
	acvp_list_type_module,
	acvp_list_type_oe,
	acvp_list_type_swdep,
	acvp_list_type_procdep,
	acvp_list_type_fwdep,
	acvp_list_type_osdep
};

struct acvp_list_types_entry {
	uint32_t id;
	const char *module_name;
	const char *proc;
	enum acvp_list_types type;
	uint32_t testid;
	struct acvp_list_types_entry *next;
};

static DEFINE_MUTEX_UNLOCKED(acvp_list_types_mutex);
static struct acvp_list_types_entry *acvp_list_types = NULL;

static const char *acvp_type_to_name(const enum acvp_list_types type)
{
	switch (type) {
	case acvp_list_type_certificate:
		return "certificate";
	case acvp_list_type_vendor:
		return "vendor";
	case acvp_list_type_address:
		return "address";
	case acvp_list_type_person:
		return "person";
	case acvp_list_type_module:
		return "module";
	case acvp_list_type_oe:
		return "OE";
	case acvp_list_type_swdep:
		return "SW dependency";
	case acvp_list_type_procdep:
		return "Proc dependency";
	case acvp_list_type_osdep:
		return "OS dependency";
	case acvp_list_type_fwdep:
		return "FW dependency";
	case acvp_list_type_unknown:
	default:
		return "unknown";
	}
}

static void acvp_list_id(const uint32_t id, const char *module_name,
			 const char *proc, const enum acvp_list_types type,
			 const uint32_t testid)
{
	if (id == 0) {
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG)
			fprintf(stdout,
				"%-57s - %-10s | %-8u | %-15s | no ID\n",
				module_name, proc, testid,
				acvp_type_to_name(type));
	} else {
		fprintf(stdout, "%-57s - %-10s | %-8u | %-15s | %-8u\n",
			module_name, proc, testid, acvp_type_to_name(type),
			acvp_id(id));
	}
}

/*
 * Sort the data before releasing it
 */
static void acvp_list_add_sort(const uint32_t id, const char *module_name,
			       const char *proc,
			       const enum acvp_list_types type,
			       const uint32_t testid)
{
	struct acvp_list_types_entry *entry, *curr, *prev;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return;

	entry->id = id;
	entry->module_name = module_name;
	entry->proc = proc;
	entry->type = type;
	entry->testid = testid;

	mutex_lock(&acvp_list_types_mutex);
	if (!acvp_list_types) {
		acvp_list_types = entry;
		goto out;
	}

	curr = acvp_list_types;
	prev = acvp_list_types;
	while (curr) {
		/* Sort based on ID */
		if (acvp_id(curr->id) > acvp_id(entry->id)) {
			if (curr == acvp_list_types) {
				acvp_list_types = entry;
			} else {
				prev->next = entry;
			}
			entry->next = curr;

			goto out;
		}

		prev = curr;
		curr = curr->next;
	}

	/* No match found */
	prev->next = entry;
	entry->next = curr;

out:
	mutex_unlock(&acvp_list_types_mutex);
}

static void acvp_list_print_sort(void)
{
	struct acvp_list_types_entry *curr, *tmp;

	mutex_lock(&acvp_list_types_mutex);
	curr = acvp_list_types;
	while (curr) {
		tmp = curr;
		acvp_list_id(curr->id, curr->module_name, curr->proc,
			     curr->type, curr->testid);

		curr = curr->next;
		free(tmp);
	}

	acvp_list_types = NULL;
	mutex_unlock(&acvp_list_types_mutex);
}

static void acvp_list_request_id(const uint32_t id, const char *module_name,
				 const char *proc,
				 const enum acvp_list_types type,
				 const uint32_t testid)
{
	if (acvp_valid_id(id))
		return;

	acvp_list_add_sort(id, module_name, proc, type, testid);
}

static void acvp_list_request_id_sparse(const uint32_t id,
					const char *module_name,
					const char *proc,
					const enum acvp_list_types type,
					const uint32_t testid)
{
#define ACVP_LIST_REQUEST_IDS_MAX 2048
	static uint32_t seen_ids[ACVP_LIST_REQUEST_IDS_MAX] = { 0 };
	static DEFINE_MUTEX_UNLOCKED(seen_ids_mutex);
	unsigned int i;
	bool seen = false;

	(void)module_name;
	(void)testid;

	if (acvp_valid_id(id))
		return;
	if (!id)
		return;

	mutex_lock(&seen_ids_mutex);
	for (i = 0; i < ACVP_LIST_REQUEST_IDS_MAX; i++) {
		if (i > 0 && seen_ids[i] == 0)
			break;

		if (seen_ids[i] == id) {
			seen = true;
			break;
		}
	}
	if (!seen)
		seen_ids[i] = id;

	mutex_unlock(&seen_ids_mutex);

	if (seen)
		return;

	if (type == acvp_list_type_certificate || type == acvp_list_type_module)
		acvp_list_add_sort(id, module_name, proc, type, testid);
	else
		acvp_list_add_sort(id, "N/A", "N/A", type, 0);
}

static void acvp_list_avail_id(const uint32_t id, const char *module_name,
			       const char *proc,
			       const enum acvp_list_types type,
			       const uint32_t testid)
{
	if (!acvp_valid_id(id))
		return;

	acvp_list_id(id, module_name, proc, type, testid);
}

static int acvp_list_certificate_id(
	const struct acvp_ctx *ctx, const struct definition *def,
	const uint32_t testid,
	void (*list_func)(const uint32_t id, const char *module_name,
			  const char *proc, const enum acvp_list_types type,
			  const uint32_t testid))
{
	const struct def_info *def_info;
	const struct def_oe *def_oe;
	const struct def_dependency *def_dep;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	const char *proc = "proc undef";
	int ret;

	def_info = def->info;
	def_oe = def->oe;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->proc_name) {
			proc = def_dep->proc_name;
			break;
		}
	}

	list_func(auth->testsession_certificate_id, def_info->module_name, proc,
		  acvp_list_type_certificate, testid);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_list_ids_cb(const struct acvp_ctx *ctx,
			    const struct definition *def, const uint32_t testid,
			    void (*list_func)(const uint32_t id,
					      const char *module_name,
					      const char *proc,
					      const enum acvp_list_types type,
					      const uint32_t testid))
{
	struct def_info *def_info;
	struct def_vendor *def_vendor;
	struct def_oe *def_oe;
	const struct def_dependency *def_dep;
	const char *proc = "proc undef";
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition data not defined\n");

	def_info = def->info;
	def_vendor = def->vendor;
	def_oe = def->oe;

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->proc_name) {
			proc = def_dep->proc_name;
			break;
		}
	}

	CKINT(acvp_list_certificate_id(ctx, def, testid, list_func));

	CKINT(acvp_def_get_vendor_id(def_vendor));
	list_func(def_vendor->acvp_vendor_id, def_info->module_name, proc,
		  acvp_list_type_vendor, testid);
	list_func(def_vendor->acvp_addr_id, def_info->module_name, proc,
		  acvp_list_type_address, testid);
	CKINT(acvp_def_put_vendor_id(def_vendor));

	CKINT(acvp_def_get_person_id(def_vendor));
	list_func(def_vendor->acvp_person_id, def_info->module_name, proc,
		  acvp_list_type_person, testid);
	CKINT(acvp_def_put_person_id(def_vendor));

	CKINT(acvp_def_get_module_id(def_info));
	list_func(def_info->acvp_module_id, def_info->module_name, proc,
		  acvp_list_type_module, testid);
	CKINT(acvp_def_put_module_id(def_info));

	CKINT(acvp_def_get_oe_id(def_oe));
	list_func(def_oe->acvp_oe_id, def_info->module_name, proc,
		  acvp_list_type_oe, testid);

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		enum acvp_list_types type = acvp_list_type_unknown;

		switch (def_dep->def_dependency_type) {
		case def_dependency_hardware:
			type = acvp_list_type_procdep;
			break;
		case def_dependency_firmware:
			type = acvp_list_type_fwdep;
			break;
		case def_dependency_os:
			type = acvp_list_type_osdep;
			break;
		case def_dependency_software:
			type = acvp_list_type_swdep;
			break;
		}

		list_func(def_dep->acvp_dep_id, def_info->module_name, proc,
			  type, testid);
	}

	CKINT(acvp_def_put_oe_id(def_oe));

out:
	return ret;
}

static int acvp_list_avaiable_id_cb(const struct acvp_ctx *ctx,
				    const struct definition *def,
				    const uint32_t testid)
{
	return acvp_list_ids_cb(ctx, def, testid, &acvp_list_avail_id);
}

DSO_PUBLIC
int acvp_list_available_ids(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-53s | %-8s | %-15s | %-8s\n", "Module Name",
		"Test ID", "ID Type", "ID");

	return acvp_process_testids(ctx, &acvp_list_avaiable_id_cb);
}

static int acvp_list_requests_cb(const struct acvp_ctx *ctx,
				 const struct definition *def,
				 const uint32_t testid)
{
	return acvp_list_ids_cb(ctx, def, testid, &acvp_list_request_id);
}

DSO_PUBLIC
int acvp_list_request_ids(const struct acvp_ctx *ctx)
{
	int ret;

	fprintf(stdout, "%-70s | %-8s | %-15s | %-8s\n", "Module Name",
		"Test ID", "Request Type", "ID");
	CKINT(acvp_process_testids(ctx, &acvp_list_requests_cb));

	acvp_list_print_sort();

out:
	return ret;
}

static int acvp_list_requests_sparse_cb(const struct acvp_ctx *ctx,
					const struct definition *def,
					const uint32_t testid)
{
	return acvp_list_ids_cb(ctx, def, testid, &acvp_list_request_id_sparse);
}

DSO_PUBLIC
int acvp_list_request_ids_sparse(const struct acvp_ctx *ctx)
{
	int ret;

	fprintf(stdout, "%-70s | %-8s | %-15s | %-8s\n", "Module Name",
		"Test ID", "Request Type", "ID");
	CKINT(acvp_process_testids(ctx, &acvp_list_requests_sparse_cb));

	acvp_list_print_sort();

out:
	return ret;
}
