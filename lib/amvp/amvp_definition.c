/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include <sys/stat.h>

#include "amvp_definition.h"
#include "amvp_internal.h"
#include "internal.h"

void amvp_def_free(struct amvp_def *amvp)
{
	if (!amvp)
		return;

	ACVP_JSON_PUT_NULL(amvp->validation_definition);
	ACVP_JSON_PUT_NULL(amvp->registration_definition);
	ACVP_JSON_PUT_NULL(amvp->sp_general);
	ACVP_JSON_PUT_NULL(amvp->sp_crypt_mod_interfaces);
	ACVP_JSON_PUT_NULL(amvp->sp_crypt_mod_spec);
	ACVP_JSON_PUT_NULL(amvp->sp_lifecycle);
	ACVP_JSON_PUT_NULL(amvp->sp_oe);
	ACVP_JSON_PUT_NULL(amvp->sp_mitigation_other_attacks);
	ACVP_JSON_PUT_NULL(amvp->sp_non_invasive_sec);
	ACVP_JSON_PUT_NULL(amvp->sp_phys_sec);
	ACVP_JSON_PUT_NULL(amvp->sp_roles_services);
	ACVP_JSON_PUT_NULL(amvp->sp_self_tests);
	ACVP_JSON_PUT_NULL(amvp->sp_ssp_mgmt);
	ACVP_JSON_PUT_NULL(amvp->sp_sw_fw_sec);

	free(amvp);
}

static int amvp_read_tester_def(const char *directory,
				struct def_vendor *vendor,
				struct amvp_def *amvp)
{
	char pathname[FILENAME_MAX];
	struct stat statbuf;
	struct json_object *tester = NULL;
	int ret = 0;

	/*
	 * If amvp was not created before, we are not filling it here either
	 * as presumably there is no AMVP operation to be done.
	 */
	CKNULL(amvp, 0);

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_FILE_REGISTRATION);

	if (stat(pathname, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "CMVP module definition not found at %s - skipping CMVP definitions\n",
		       pathname);
		ret = -EOPNOTSUPP;
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading configuration file %s\n",
	       pathname);

	/* Read configuration data in */
	tester = json_object_from_file(pathname);
	CKNULL(tester, -EFAULT);

	CKINT(acvp_def_get_vendor_id(vendor));
	if (vendor->acvp_vendor_id == 0) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		        "The vendor JSON definition does not contain a vendor ID! It is required to have one at this point which implies that as of now, no AMVP operation is possible. Thus, please obtain such an ID with acvp-proxy --sync-meta.\n");
		ret = -EOPNOTSUPP;
		goto unlock;
	}

	CKINT_ULCK(json_object_object_add(tester, "vendorId",
		json_object_new_int((int)vendor->acvp_vendor_id)));

	amvp->registration_definition = json_object_new_array();
	CKNULL_ULOCK(amvp->registration_definition, -ENOMEM);
	CKINT_ULCK(acvp_req_add_version(amvp->registration_definition));
	CKINT_ULCK(json_object_array_add(amvp->registration_definition, tester));
	tester = NULL;

unlock:
	ret |= acvp_def_put_vendor_id(vendor);
out:
	ACVP_JSON_PUT_NULL(tester);
	return ret;
}

static int amvp_read_validation_def(const char *directory,
				    const struct def_info *info,
				    struct amvp_def *amvp)
{
	char pathname[FILENAME_MAX];
	struct stat statbuf;
	struct json_object *validation = NULL, *module_def, *seclevel;
	unsigned int i, level_val, overall_level = 4;
	const char *str;
	int ret = 0;

	CKNULL(info, -EINVAL);

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_FILE_VAL_INFO);

	if (stat(pathname, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "CMVP module definition not found at %s - skipping CMVP definitions\n",
		       pathname);
		ret = -EOPNOTSUPP;
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading configuration file %s\n",
	       pathname);

	/* Read configuration data in */
	validation = json_object_from_file(pathname);
	CKNULL(validation, -EFAULT);

	/*
	 * Now add some additional internal settings to the meta data.
	 */
	CKINT(json_object_object_add(validation, "schemaVersion",
				     json_object_new_string("Draft 1")));

	CKINT(json_find_key(validation, "moduleInfo", &module_def,
			    json_type_object));

	CKINT(json_object_object_add(module_def, "name",
		json_object_new_string(info->orig_module_name)));
	CKINT(json_object_object_add(module_def, "count",
				     json_object_new_int(1)));
	CKINT(json_object_object_add(module_def, "description",
		json_object_new_string(info->module_description)));

	CKINT(acvp_module_type_enum_to_name(info->module_type, &str));
	CKINT(json_object_object_add(module_def, "type",
				     json_object_new_string(str)));
	CKINT(json_object_object_add(module_def, "itar",
				     json_object_new_boolean(0)));

	//TODO: it is currently unclear what that is
	CKINT(json_object_object_add(module_def, "opEnvType",
				     json_object_new_string("opEnvType1")));
	CKINT(json_object_object_add(module_def, "submissionLevel",
				     json_object_new_string("Level 1")));

	CKINT(json_find_key(validation, "secLevels", &seclevel,
			    json_type_array));

	/*
	 * Search through all security levels and determine the overall security
	 * level by obtaining the lowest level.
	 */
	for (i = 0; i < json_object_array_length(seclevel); i++) {
		struct json_object *level =
			json_object_array_get_idx(seclevel, i);

		if (!json_object_is_type(level, json_type_object)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "JSON data type %s does not match expected type %s\n",
			       json_type_to_name(json_object_get_type(level)),
			       json_type_to_name(json_type_object));
			ret = -EINVAL;
			goto out;
		}

		CKINT(json_get_uint(level, "level", &level_val));
		if (level_val < overall_level)
			overall_level = level_val;
	}

	/* Now set the overall level. */
	CKINT(json_object_object_add(module_def, "overallSecurityLevel",
				     json_object_new_int((int)overall_level)));


	amvp->validation_definition = json_object_new_array();
	CKNULL(amvp->validation_definition, -ENOMEM);
	CKINT(acvp_req_add_version(amvp->validation_definition));
	CKINT(json_object_array_add(amvp->validation_definition, validation));
	validation = NULL;

out:
	ACVP_JSON_PUT_NULL(validation);
	return ret;
}

static int amvp_read_sp_one(const char *pathname,
			    struct json_object **out)
{
	struct stat statbuf;
	struct json_object *data;
	int ret = 0;

	if (*out) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Refusing to overwrite used memory pointer\n");
		return -EFAULT;
	}

	if (stat(pathname, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "CMVP module definition not found at %s - skipping CMVP definitions\n",
		       pathname);
		/* This is no error as we allow the absence of an SP part */
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading SP file %s\n",
	       pathname);

	/* Read configuration data in */
	data = json_object_from_file(pathname);
	CKNULL(data, -EFAULT);

	*out = data;

out:
	return ret;
}

static int amvp_read_sp_def(const char *directory, struct amvp_def *amvp)
{
	char pathname[FILENAME_MAX];
	int ret = 0;

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_GENERAL);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_general));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_CRYPT_MOD_INTERFACES);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_crypt_mod_interfaces));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_CRYPT_MOD_SPEC);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_crypt_mod_spec));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_LIFECYCLE);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_lifecycle));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_OE);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_oe));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_MITIGATION_OTHER_ATTACKS);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_mitigation_other_attacks));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_NON_INVASIVE_SEC);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_non_invasive_sec));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_PHYS_SEC);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_phys_sec));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_ROLES_SERVICES);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_roles_services));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SP_SELF_TESTS);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_self_tests));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SSP_MGMT);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_ssp_mgmt));

	snprintf(pathname, sizeof(pathname), "%s/%s/%s", directory,
		 AMVP_DEF_DIR_CMVP, AMVP_DEF_SW_FW_SEC);
	CKINT(amvp_read_sp_one(pathname, &amvp->sp_sw_fw_sec));

out:
	return ret;
}

int amvp_def_config(const char *directory, const struct definition *def,
		    struct amvp_def **amvp_out)
{
	struct amvp_def *amvp = NULL;
	int ret = 0;

	CKNULL_LOG(directory, -EINVAL, "Configuration directory missing\n");
	CKNULL_LOG(def, -EINVAL, "Definition information buffer missing\n");
	CKNULL_LOG(amvp_out, -EINVAL, "Destination buffer missing\n");

	*amvp_out = NULL;

	amvp = calloc(1, sizeof(struct amvp_def));
	CKNULL(amvp, -ENOMEM);

	/* Read the validation meta data */
	ret = amvp_read_validation_def(directory, def->info, amvp);

	/* Read the registration meta data */
	if (!ret)
		ret = amvp_read_tester_def(directory, def->vendor, amvp);

	if (!ret)
		ret = amvp_read_sp_def(directory, amvp);

	if (ret) {
		/*
		 * EOPNOTSUPP is used to indicate a missing ID - this error will
		 * not be relayed on as simply the AMVP support is not present
		 * for this definition.
		 */
		if (ret == -EOPNOTSUPP)
			ret = 0;
		goto out;
	}

	*amvp_out = amvp;
	amvp = NULL;

out:
	amvp_def_free(amvp);
	return ret;
}
