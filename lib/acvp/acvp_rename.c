/* Rename of module references that occur on different places
 *
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "definition.h"
#include "internal.h"

static int acvp_export_def_search_new(const struct acvp_testid_ctx *testid_ctx)
{
	const struct definition *def = testid_ctx->def;
	struct def_info *info = def->info;
	char *tmp = NULL, *tmp2 = NULL, *tmp3 = NULL, *tmp4 = NULL;
	int ret;

	/* Store the update in the new target */
	if (info->module_name_newname) {
		tmp = info->module_name;
		info->module_name = info->module_name_newname;
	}
	if (info->module_name_filesafe_newname) {
		tmp2 = info->module_name_filesafe;
		info->module_name_filesafe = info->module_name_filesafe_newname;
	}

	if (info->module_version_newname) {
		tmp3 = info->module_version;
		info->module_version = info->module_version_newname;
	}

	if (info->module_version_filesafe_newname) {
		tmp4 = info->module_version_filesafe;
		info->module_version_filesafe =
			info->module_version_filesafe_newname;
	}

	/* Update definition - temporarily switch the names*/
	ret = acvp_export_def_search(testid_ctx);

	if (tmp)
		info->module_name = tmp;
	if (tmp2)
		info->module_name_filesafe = tmp2;
	if (tmp3)
		info->module_version = tmp3;
	if (tmp4)
		info->module_version_filesafe = tmp4;

	return ret;
}

static int acvp_rename_generic(const struct acvp_testid_ctx *testid_ctx,
			       char **curr_ptr, const char *newname)
{
	char *curr_name = *curr_ptr;
	char *newname_modify = *curr_ptr;
	int ret;

	CKNULL(newname, 0);

	if (!newname_modify) {
		CKINT(acvp_duplicate(&newname_modify, newname));

		/* Update names */
		*curr_ptr = newname_modify;
	}

	/* Update definition */
	CKINT(acvp_export_def_search_new(testid_ctx));

	logger_status(
		LOGGER_C_ANY,
		"Rename of OE name for testID %u from %s to %s completed\n",
		testid_ctx->testid, curr_name, newname_modify);

	/*
	 * We deliberately do not touch the module definition JSON files
	 * as they are treated as user input to the proxy.
	 */

	logger_status(
		LOGGER_C_ANY,
		"If the name is already registered with the ACVP server and you want to update it with \"--update-definition oe\" remember to perform TWO rounds of update, one for the software dependency and one for the OE name!\n");

out:
	if (ret) {
		if (newname_modify)
			free(newname_modify);
		*curr_ptr = curr_name;
	} else {
		if (curr_name != *curr_ptr)
			free(curr_name);
	}
	return ret;
}

static int acvp_rename_execenv_final(const struct definition *def)
{
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;
	bool changed = false;

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name && def_dep->name_newname) {
			ACVP_PTR_FREE_NULL(def_dep->name);
			def_dep->name = def_dep->name_newname;
			def_dep->name_newname = NULL;
			changed = true;
		}
	}

	if (changed)
		CKINT(acvp_def_update_oe_config(oe));

out:
	return ret;
}

static int acvp_rename_execenv(const struct acvp_testid_ctx *testid_ctx,
			       const char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(testid_ctx,
						  &def_dep->name_newname,
						  newname));
			break;
		}
	}

out:
	return ret;
}

static int acvp_rename_procname_final(const struct definition *def)
{
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;
	bool changed = false;

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name && def_dep->proc_name_newname) {
			ACVP_PTR_FREE_NULL(def_dep->proc_name);
			def_dep->proc_name = def_dep->proc_name_newname;
			def_dep->proc_name_newname = NULL;
			changed = true;
		}
	}

	if (changed)
		CKINT(acvp_def_update_oe_config(oe));

out:
	return ret;
}

static int acvp_rename_procname(const struct acvp_testid_ctx *testid_ctx,
				const char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_name_newname,
				newname));
			break;
		}
	}

out:
	return ret;
}

static int acvp_rename_procfamily_final(const struct definition *def)
{
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;
	bool changed = false;

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name && def_dep->proc_family_newname) {
			ACVP_PTR_FREE_NULL(def_dep->proc_family);
			def_dep->proc_family = def_dep->proc_family_newname;
			def_dep->proc_family_newname = NULL;;
			changed = true;
		}
	}

	if (changed)
		CKINT(acvp_def_update_oe_config(oe));

out:
	return ret;
}

static int acvp_rename_procfamily(const struct acvp_testid_ctx *testid_ctx,
				  const char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_family_newname,
				newname));
			break;
		}
	}

out:
	return ret;
}

static int acvp_rename_procseries_final(const struct definition *def)
{
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;
	bool changed = false;

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name && def_dep->proc_series_newname) {
			ACVP_PTR_FREE_NULL(def_dep->proc_series);
			def_dep->proc_series = def_dep->proc_series_newname;
			def_dep->proc_series_newname = NULL;
			changed = true;
		}
	}

	if (changed)
		CKINT(acvp_def_update_oe_config(oe));

out:
	return ret;
}

static int acvp_rename_procseries(const struct acvp_testid_ctx *testid_ctx,
				  const char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret = 0;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_series_newname,
				newname));
			break;
		}
	}

out:
	return ret;
}

static int acvp_rename_name_final(const struct definition *def)
{
	struct def_info *info = def->info;
	int ret = 0;
	bool changed = false;

	if (info->module_name_filesafe_newname) {
		ACVP_PTR_FREE_NULL(info->module_name_filesafe);
		info->module_name_filesafe =
			info->module_name_filesafe_newname;
		info->module_name_filesafe_newname = NULL;
		changed = true;
	}

	if (info->orig_module_name_newname) {
		ACVP_PTR_FREE_NULL(info->orig_module_name);
		info->orig_module_name = info->orig_module_name_newname;
		info->orig_module_name_newname = NULL;
		changed = true;
	}

	if (info->module_name_newname) {
		ACVP_PTR_FREE_NULL(info->module_name);
		info->module_name = info->module_name_newname;
		info->module_name_newname = NULL;
		changed = true;
	}

	if (changed)
		CKINT(acvp_def_update_module_config(info));

out:
	return ret;
}

static int acvp_rename_name(const struct acvp_testid_ctx *testid_ctx,
			    const char *newname)
{
	const struct definition *def = testid_ctx->def;
	const struct def_algo_map *map = def->uninstantiated_def;
	struct def_info *info = def->info;
	char *curr_name = info->module_name;
	int ret;

	CKNULL(newname, 0);
	CKNULL_LOG(map, -EFAULT, "Uninstantiated definition not found\n");

	/* Create the new module name string */
	if (!info->module_name_filesafe_newname)
		CKINT(acvp_def_module_name(&info->module_name_filesafe_newname,
					   newname, map->impl_name));
	if (!info->module_name_newname)
		CKINT(acvp_def_module_name(&info->module_name_newname, newname,
					   map->impl_name));
	if (!info->orig_module_name_newname)
		CKINT(acvp_def_module_name(&info->orig_module_name_newname,
					   newname, NULL));

	/* Rename directories */
	CKINT(ds->acvp_datastore_rename_name(
		testid_ctx, info->module_name_filesafe_newname));

	CKINT(acvp_export_def_search_new(testid_ctx));

	logger_status(LOGGER_C_ANY,
		      "Rename of name for testID %u from %s to %s completed\n",
		      testid_ctx->testid, curr_name,
		      info->module_name_filesafe_newname);

	/*
	 * We deliberately do not touch the module definition JSON files
	 * as they are treated as user input to the proxy.
	 */

out:
	return ret;
}

static int acvp_rename_version_final(const struct definition *def)
{
	struct def_info *info = def->info;
	int ret = 0;
	bool changed = false;

	if (info->module_version_filesafe_newname) {
		ACVP_PTR_FREE_NULL(info->module_version_filesafe);
		info->module_version_filesafe =
			info->module_version_filesafe_newname;
		info->module_version_filesafe_newname = NULL;
		changed = true;
	}

	if (info->module_version_newname) {
		ACVP_PTR_FREE_NULL(info->module_version);
		info->module_version = info->module_version_newname;
		info->module_version_newname = NULL;
		changed = true;
	}

	if (changed)
		CKINT(acvp_def_update_module_config(info));

out:
	return ret;
}

static int acvp_rename_version(const struct acvp_testid_ctx *testid_ctx,
			       const char *newversion)
{
	const struct definition *def = testid_ctx->def;
	struct def_info *info = def->info;
	char *curr_version = info->module_version;
	int ret;

	CKNULL(newversion, 0);

	/* Create the new module version string */
	if (!info->module_version_filesafe_newname)
		CKINT(acvp_duplicate(&info->module_version_filesafe_newname,
				     newversion));
	if (!info->module_version_newname)
		CKINT(acvp_duplicate(&info->module_version_newname,
				     newversion));

	/* Rename directories */
	CKINT(ds->acvp_datastore_rename_version(
		testid_ctx, info->module_version_filesafe_newname));

	CKINT(acvp_export_def_search_new(testid_ctx));

	logger_status(
		LOGGER_C_ANY,
		"Rename of version for testID %u from %s to %s completed\n",
		testid_ctx->testid, curr_version,
		info->module_version_filesafe_newname);

	/*
	 * We deliberately do not touch the module definition JSON files
	 * as they are treated as user input to the proxy.
	 */

out:
	return ret;
}

static int acvp_rename_module_cb(const struct acvp_ctx *ctx,
				 const struct definition *def,
				 const uint32_t testid)
{
	const struct acvp_rename_ctx *rename_ctx = ctx->rename;
	struct acvp_testid_ctx testid_ctx;
	int ret = 0;

	CKNULL(rename_ctx, -EINVAL);

	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;

	CKINT(acvp_rename_version(&testid_ctx, rename_ctx->moduleversion_new));
	CKINT(acvp_rename_name(&testid_ctx, rename_ctx->modulename_new));
	CKINT(acvp_rename_execenv(&testid_ctx, rename_ctx->oe_env_name_new));
	CKINT(acvp_rename_procname(&testid_ctx, rename_ctx->proc_name_new));
	CKINT(acvp_rename_procseries(&testid_ctx, rename_ctx->proc_series_new));
	CKINT(acvp_rename_procfamily(&testid_ctx, rename_ctx->proc_family_new));

out:
	return ret;
}

static int acvp_rename_module_final_cb(const struct acvp_ctx *ctx,
				       const struct definition *def,
				       const uint32_t testid)
{
	int ret = 0;

	(void)ctx;
	(void)testid;

	CKINT(acvp_rename_version_final(def));
	CKINT(acvp_rename_name_final(def));
	CKINT(acvp_rename_execenv_final(def));
	CKINT(acvp_rename_procname_final(def));
	CKINT(acvp_rename_procseries_final(def));
	CKINT(acvp_rename_procfamily_final(def));

out:
	return ret;
}

DSO_PUBLIC
int acvp_rename_module(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_process_testids(ctx, &acvp_rename_module_cb));
	CKINT(acvp_process_testids(ctx, &acvp_rename_module_final_cb));

out:
	return ret;
}
