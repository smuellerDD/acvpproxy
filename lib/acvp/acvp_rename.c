/* Rename of module references that occur on different places
 *
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

static int acvp_rename_generic(const struct acvp_testid_ctx *testid_ctx,
			       char **curr_ptr, const char *newname)
{
	char *curr_name = *curr_ptr;
	char *newname_modify = NULL;
	int ret;

	CKNULL(newname, 0);

	CKINT(acvp_duplicate(&newname_modify, newname));

	/* Update names */
	*curr_ptr = newname_modify;

	/* Update definition */
	CKINT(acvp_export_def_search(testid_ctx));

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

static int acvp_rename_execenv(const struct acvp_testid_ctx *testid_ctx,
			       const char *newname)
{
	const struct definition *def = testid_ctx->def;
	struct def_oe *oe = def->oe;
	struct def_dependency *def_dep;
	int ret;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(testid_ctx, &def_dep->name,
						  newname));
			break;
		}
	}

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
	int ret;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_name, newname));
			break;
		}
	}

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
	int ret;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_family, newname));
			break;
		}
	}

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
	int ret;

	CKNULL(newname, 0);

	if (oe->config_file_version > 1) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Rename of OE dependency for complex definitions not supported\n");
		return -EOPNOTSUPP;
	}

	for (def_dep = oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name) {
			CKINT(acvp_rename_generic(
				testid_ctx, &def_dep->proc_series, newname));
			break;
		}
	}

	CKINT(acvp_def_update_oe_config(oe));

out:
	return ret;
}

static int acvp_rename_name(const struct acvp_testid_ctx *testid_ctx,
			    const char *newname)
{
	const struct definition *def = testid_ctx->def;
	const struct def_algo_map *map = def->uninstantiated_def;
	struct def_info *info = def->info;
	char *newname_modify = NULL;
	char *newname_unmodify = NULL;
	char *newname_orig = NULL;
	char *curr_name = info->module_name;
	char *curr_name_filesafe = info->module_name_filesafe;
	char *curr_name_orig = info->orig_module_name;
	int ret;

	CKNULL(newname, 0);
	CKNULL_LOG(map, -EFAULT, "Uninstantiated definition not found\n");

	/* Create the new module name string */
	CKINT(acvp_def_module_name(&newname_modify, newname, map->impl_name));
	CKINT(acvp_def_module_name(&newname_unmodify, newname, map->impl_name));
	CKINT(acvp_def_module_name(&newname_orig, newname, NULL));

	/* Rename directories */
	CKINT(ds->acvp_datastore_rename_name(testid_ctx, newname_modify));

	/* Update names */
	info->module_name_filesafe = newname_modify;
	info->module_name = newname_unmodify;
	info->orig_module_name = newname_orig;

	/* Update definition */
	CKINT(acvp_export_def_search(testid_ctx));
	CKINT(acvp_def_update_module_config(info));

	logger_status(LOGGER_C_ANY,
		      "Rename of name for testID %u from %s to %s completed\n",
		      testid_ctx->testid, curr_name, newname_modify);

	/*
	 * We deliberately do not touch the module definition JSON files
	 * as they are treated as user input to the proxy.
	 */

out:
	if (ret) {
		if (newname_modify)
			free(newname_modify);
		if (newname_unmodify)
			free(newname_unmodify);
		if (newname_orig)
			free(newname_orig);

		info->module_name = curr_name;
		info->module_name_filesafe = curr_name_filesafe;
		info->orig_module_name = curr_name_orig;
	} else {
		if (curr_name != info->module_name)
			free(curr_name);
		if (curr_name_filesafe != info->module_name_filesafe)
			free(curr_name_filesafe);
		if (curr_name_orig != info->orig_module_name)
			free(curr_name_orig);
	}

	return ret;
}

static int acvp_rename_version(const struct acvp_testid_ctx *testid_ctx,
			       const char *newversion)
{
	const struct definition *def = testid_ctx->def;
	struct def_info *info = def->info;
	char *newversion_modify = NULL;
	char *newversion_unmodify = NULL;
	char *curr_version = info->module_version;
	char *curr_version_filesafe = info->module_version_filesafe;
	int ret;

	CKNULL(newversion, 0);

	/* Create the new module version string */
	CKINT(acvp_duplicate(&newversion_modify, newversion));
	CKINT(acvp_duplicate(&newversion_unmodify, newversion));

	/* Rename directories */
	CKINT(ds->acvp_datastore_rename_version(testid_ctx, newversion_modify));

	/* Update names */
	info->module_version_filesafe = newversion_modify;
	info->module_version = newversion_unmodify;

	/* Update definition */
	CKINT(acvp_export_def_search(testid_ctx));
	CKINT(acvp_def_update_module_config(info));

	logger_status(
		LOGGER_C_ANY,
		"Rename of version for testID %u from %s to %s completed\n",
		testid_ctx->testid, curr_version, newversion_modify);

	/*
	 * We deliberately do not touch the module definition JSON files
	 * as they are treated as user input to the proxy.
	 */

out:
	if (ret) {
		if (newversion_modify)
			free(newversion_modify);
		if (newversion_unmodify)
			free(newversion_unmodify);

		info->module_version = curr_version;
		info->module_version_filesafe = curr_version_filesafe;
	} else {
		if (curr_version != info->module_version)
			free(curr_version);
		if (curr_version_filesafe != info->module_version_filesafe)
			free(curr_version_filesafe);
	}

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

DSO_PUBLIC
int acvp_rename_module(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_process_testids(ctx, &acvp_rename_module_cb));

out:
	return ret;
}
