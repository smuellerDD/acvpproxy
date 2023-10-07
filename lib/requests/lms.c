/* JSON generator for LMS ciphers
 *
 * Copyright (C) 2023 - 2023, Joachim Vandersmissen <joachim@atsec.com>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

static int acvp_req_lms_lms_modes(const unsigned int lms_modes,
				  struct json_object *array)
{
	int ret = 0;

	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M24_H5) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M24_H5")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M24_H10) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M24_H10")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M24_H15) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M24_H15")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M24_H20) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M24_H20")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M24_H25) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M24_H25")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M32_H5) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M32_H5")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M32_H10) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M32_H10")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M32_H15) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M32_H15")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M32_H20) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M32_H20")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHA256_M32_H25) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHA256_M32_H25")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M24_H5) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M24_H5")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M24_H10) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M24_H10")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M24_H15) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M24_H15")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M24_H20) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M24_H20")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M24_H25) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M24_H25")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M32_H5) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M32_H5")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M32_H10) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M32_H10")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M32_H15) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M32_H15")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M32_H20) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M32_H20")));
	}
	if (lms_modes & DEF_ALG_LMS_LMS_SHAKE_M32_H25) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMS_SHAKE_M32_H25")));
	}

out:
	return ret;
}

static int acvp_req_lms_lmots_modes(const unsigned int lmots_modes,
				    struct json_object *array)
{
	int ret = 0;

	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N24_W1) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N24_W1")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N24_W2) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N24_W2")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N24_W4) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N24_W4")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N24_W8) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N24_W8")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N32_W1) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N32_W1")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N32_W2) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N32_W2")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N32_W4) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N32_W4")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHA256_N32_W8) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHA256_N32_W8")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N24_W1) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N24_W1")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N24_W2) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N24_W2")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N24_W4) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N24_W4")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N24_W8) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N24_W8")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N32_W1) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N32_W1")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N32_W2) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N32_W2")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N32_W4) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N32_W4")));
	}
	if (lmots_modes & DEF_ALG_LMS_LMOTS_SHAKE_N32_W8) {
		CKINT(json_object_array_add(array,
				json_object_new_string("LMOTS_SHAKE_N32_W8")));
	}

out:
	return ret;
}

static int acvp_req_lms_capabilities(const struct def_algo_lms *lms,
				     struct json_object *entry)
{
	struct json_object *caps, *lms_modes, *lmots_modes;
	int ret = 0;

	caps = json_object_new_object();
	CKNULL(caps, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps));

	lms_modes = json_object_new_array();
	CKNULL(lms_modes, -ENOMEM);
	CKINT(acvp_req_lms_lms_modes(lms->lms_modes, lms_modes));
	CKINT(json_object_object_add(caps, "lmsModes", lms_modes));

	lmots_modes = json_object_new_array();
	CKNULL(lmots_modes, -ENOMEM);
	CKINT(acvp_req_lms_lmots_modes(lms->lmots_modes, lmots_modes));
	CKINT(json_object_object_add(caps, "lmOtsModes", lmots_modes));
out:
	return ret;
}

static int acvp_req_lms_specific_capabilities(const struct def_algo_lms *lms,
					      struct json_object *entry)
{
	struct json_object *specific_caps_array, *specific_cap;
	struct json_object *tmp = NULL;
	unsigned int i;
	int ret = 0;

	specific_caps_array = json_object_new_array();
	CKNULL(specific_caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "specificCapabilities",
				     specific_caps_array));

	// This temporary array is used for the sole purpose of parsing the
	// lms_mode and lmots_mode integers. It is never added to any JSON
	// object, the strings inside this array are simply extracted and then
	// removed.
	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);

	for (i = 0; i < lms->specific_capabilities_num; i++) {
		const struct def_algo_lms_specific_caps *specific_caps =
				lms->specific_capabilities + i;

		specific_cap = json_object_new_object();
		CKNULL(specific_cap, -ENOMEM);
		CKINT(json_object_array_add(specific_caps_array, specific_cap));

		CKINT(acvp_req_lms_lms_modes(specific_caps->lms_mode, tmp));
		if (json_object_array_length(tmp) != 1) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "LMS: specific capability %d must have exactly one lms_mode\n", i);
			ret = -EINVAL;
			goto out;
			break;
		}

		// We must use json_object_get to grab ownership of the entry.
		CKINT(json_object_object_add(specific_cap, "lmsMode",
			json_object_get(json_object_array_get_idx(tmp, 0))));
		CKINT(json_object_array_del_idx(tmp, 0, 1));

		CKINT(acvp_req_lms_lmots_modes(specific_caps->lmots_mode, tmp));
		if (json_object_array_length(tmp) != 1) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "LMS: specific capability %d must have exactly one lmots_mode\n", i);
			ret = -EINVAL;
			goto out;
			break;
		}

		// We must use json_object_get to grab ownership of the entry.
		CKINT(json_object_object_add(specific_cap, "lmOtsMode",
			json_object_get(json_object_array_get_idx(tmp, 0))));
		CKINT(json_object_array_del_idx(tmp, 0, 1));
	}

out:
	ACVP_JSON_PUT_NULL(tmp);
	return ret;
}

/*
 * Generate algorithm entry for LMS
 */
static int _acvp_req_set_algo_lms(const struct def_algo_lms *lms,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool full,
				  bool publish)
{
	int ret = 0;

	if (full) {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("LMS")));

	switch (lms->lms_mode) {
	case DEF_ALG_LMS_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		break;
	case DEF_ALG_LMS_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		break;
	case DEF_ALG_LMS_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "LMS: Unknown LMS mode definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if (full) {
		if ((lms->lms_modes || lms->lmots_modes) &&
		    lms->specific_capabilities_num > 0) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "LMS: either general or specific capabilities must be provided, not both\n");
			ret = -EINVAL;
			goto out;
		}

		if (lms->lms_modes || lms->lmots_modes) {
			CKINT(acvp_req_lms_capabilities(lms, entry));
		}
		if (lms->specific_capabilities_num > 0) {
			CKINT(acvp_req_lms_specific_capabilities(lms, entry));
		}
	}

	CKINT(acvp_req_gen_prereq(lms->prereqvals, lms->prereqvals_num, deps,
				  entry, publish));

out:
	return ret;
}

int acvp_list_algo_lms(const struct def_algo_lms *lms,
		       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "LMS"));
	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;
	tmp->prereqs = lms->prereqvals;
	tmp->prereq_num = lms->prereqvals_num;

	switch (lms->lms_mode) {
	case DEF_ALG_LMS_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_LMS_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	case DEF_ALG_LMS_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "LMS: Unknown LMS mode definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

out:
	return ret;
}

int acvp_req_set_prereq_lms(const struct def_algo_lms *lms,
			    const struct acvp_test_deps *deps,
			    struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_lms(lms, deps, entry, false, publish);
}

int acvp_req_set_algo_lms(const struct def_algo_lms *lms,
			  struct json_object *entry)
{
	return _acvp_req_set_algo_lms(lms, NULL, entry, true, false);
}
