/* List all pending request IDs
 *
 * Copyright (C) 2019 - 2020, Stephan Mueller <smueller@chronox.de>
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

static void acvp_list_id(const uint32_t id, const char *module_name,
			 const char *name, const uint32_t testid)
{
	if (id == 0) {
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG)
			fprintf(stdout, "%-40s | %-8u | %-15s | no ID\n",
				module_name, testid, name);
	} else {
		fprintf(stdout, "%-40s | %-8u | %-15s | %-8u\n",
			module_name, testid, name, acvp_id(id));
	}
}

static void acvp_list_request_id(const uint32_t id, const char *module_name,
				 const char *name, const uint32_t testid)
{
	if (acvp_valid_id(id))
		return;

	acvp_list_id(id, module_name, name, testid);
}

static void acvp_list_avail_id(const uint32_t id, const char *module_name,
			       const char *name, const uint32_t testid)
{
	if (!acvp_valid_id(id))
		return;

	acvp_list_id(id, module_name, name, testid);
}

static int acvp_list_certificate_id(const struct acvp_ctx *ctx,
				    const struct definition *def,
				    const uint32_t testid,
				    void(*list_func)(const uint32_t id,
						     const char *module_name,
						     const char *name,
						     const uint32_t testid))
{
	const struct def_info *def_info;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	def_info = def->info;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	list_func(auth->testsession_certificate_id, def_info->module_name,
		  "certificate", testid);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_list_ids_cb(const struct acvp_ctx *ctx,
			    const struct definition *def,
			    const uint32_t testid,
			    void(*list_func)(const uint32_t id,
					     const char *module_name,
					     const char *name,
					     const uint32_t testid))
{
	struct def_info *def_info;
	struct def_vendor *def_vendor;
	struct def_oe *def_oe;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition data not defined\n");

	def_info = def->info;
	def_vendor = def->vendor;
	def_oe = def->oe;

	CKINT(acvp_list_certificate_id(ctx, def, testid, list_func));

	CKINT(acvp_def_get_vendor_id(def_vendor));
	list_func(def_vendor->acvp_vendor_id, def_info->module_name, "vendor",
		  testid);
	list_func(def_vendor->acvp_addr_id, def_info->module_name, "address",
		  testid);
	CKINT(acvp_def_put_vendor_id(def_vendor));

	CKINT(acvp_def_get_person_id(def_vendor));
	list_func(def_vendor->acvp_person_id, def_info->module_name, "person",
		  testid);
	CKINT(acvp_def_put_person_id(def_vendor));

	CKINT(acvp_def_get_module_id(def_info));
	list_func(def_info->acvp_module_id, def_info->module_name, "module",
		  testid);
	CKINT(acvp_def_put_module_id(def_info));

	CKINT(acvp_def_get_oe_id(def_oe));
	list_func(def_oe->acvp_oe_id, def_info->module_name, "OE", testid);
	list_func(def_oe->acvp_oe_dep_sw_id, def_info->module_name,
		  "SW dependency", testid);
	list_func(def_oe->acvp_oe_dep_proc_id, def_info->module_name,
		  "Proc dependency", testid);
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
	fprintf(stdout, "%-40s | %-8s | %-15s | %-8s\n",
			"Module Name", "Test ID", "ID Type", "ID");

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
	fprintf(stdout, "%-40s | %-8s | %-15s | %-8s\n",
			"Module Name", "Test ID", "Request Type", "ID");
	return acvp_process_testids(ctx, &acvp_list_requests_cb);
}
