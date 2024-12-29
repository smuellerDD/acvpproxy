/* JSON request generator for SLH-DSA
 *
 * Copyright (C) 2024, Joachim Vandersmissen <joachim@atsec.com>
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

static int acvp_req_slh_dsa_parameter_set(unsigned int parameter_set,
					  struct json_object *entry)
{
	struct json_object *parameter_sets_array;
	int ret = 0;

	parameter_sets_array = json_object_new_array();
	CKNULL(parameter_sets_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSets",
				     parameter_sets_array));

	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_128S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-128s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_128S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-128s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_128F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-128f")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_128F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-128f")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_192S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-192s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_192S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-192s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_192F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-192f")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_192F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-192f")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_256S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-256s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_256S) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-256s")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHA2_256F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHA2-256f")));
	}
	if (parameter_set & DEF_ALG_SLH_DSA_SHAKE_256F) {
		CKINT(json_object_array_add(parameter_sets_array,
					    json_object_new_string("SLH-DSA-SHAKE-256f")));
	}

out:
	return ret;
}

int acvp_list_algo_slh_dsa(const struct def_algo_slh_dsa *slh_dsa,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	unsigned int i, idx = 0;
	unsigned int all_parameter_sets = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "SLH-DSA"));
	switch (slh_dsa->slh_dsa_mode) {
	case DEF_ALG_SLH_DSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		for (i = 0; i < slh_dsa->capabilities_num; i++) {
			const struct def_algo_slh_dsa_caps *caps =
					slh_dsa->capabilities.keygen + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	case DEF_ALG_SLH_DSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		for (i = 0; i < slh_dsa->capabilities_num; i++) {
			const struct def_algo_slh_dsa_caps *caps =
					slh_dsa->capabilities.siggen + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	case DEF_ALG_SLH_DSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		for (i = 0; i < slh_dsa->capabilities_num; i++) {
			const struct def_algo_slh_dsa_caps *caps =
					slh_dsa->capabilities.sigver + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "SLH-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if ((all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_128S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_128S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_128F) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_128F)) {
		tmp->keylen[idx++] = 128;
	}
	if ((all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_192S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_192S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_192F) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_192F)) {
		tmp->keylen[idx++] = 192;
	}
	if ((all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_256S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_256S) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHA2_256F) ||
	    (all_parameter_sets & DEF_ALG_SLH_DSA_SHAKE_256F)) {
		tmp->keylen[idx++] = 256;
	}
	tmp->keylen[idx] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int acvp_req_set_prereq_slh_dsa(const struct def_algo_slh_dsa *slh_dsa,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
#if 0
	int ret;

	CKINT(acvp_req_gen_prereq(&slh_dsa->prereqvals, 1, deps, entry, publish));

out:
	return ret;
#else
	(void)slh_dsa;
	(void)deps;
	(void)publish;
	json_object_object_add(entry, "algorithm",
			       json_object_new_string("SLH-DSA"));
	return 0;
#endif
}

static int acvp_req_slh_dsa_sig_caps(const struct def_algo_slh_dsa_caps *caps,
				     struct json_object *caps_entry)
{
	int ret = 0;

	CKINT(acvp_req_slh_dsa_parameter_set(caps->parameter_set, caps_entry));
	CKINT(acvp_req_algo_int_array(caps_entry, caps->messagelength,
				      "messageLength"));

out:
	return ret;
}

static int acvp_req_slh_dsa_siggen(const struct def_algo_slh_dsa *slh_dsa,
				   struct json_object *entry)
{
	struct json_object *array;
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	for (i = 0; i < slh_dsa->capabilities_num; i++) {
		const struct def_algo_slh_dsa_caps *caps =
						slh_dsa->capabilities.siggen + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_slh_dsa_sig_caps(caps, caps_entry));
	}

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "deterministic", array));
	if (slh_dsa->deterministic & DEF_ALG_SLH_DSA_SIGGEN_NON_DETERMINISTIC) {
		CKINT(json_object_array_add(array,
					    json_object_new_boolean(false)));
	}
	if (slh_dsa->deterministic & DEF_ALG_SLH_DSA_SIGGEN_DETERMINISTIC) {
		CKINT(json_object_array_add(array,
					    json_object_new_boolean(true)));
	}

out:
	return ret;
}

static int acvp_req_slh_dsa_sigver(const struct def_algo_slh_dsa *slh_dsa,
				   struct json_object *entry)
{
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	for (i = 0; i < slh_dsa->capabilities_num; i++) {
		const struct def_algo_slh_dsa_caps *caps =
						slh_dsa->capabilities.sigver + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_slh_dsa_sig_caps(caps, caps_entry));
	}

out:
	return ret;
}

/*
 * Generate algorithm entry for SLH-DSA
 */
int acvp_req_set_algo_slh_dsa(const struct def_algo_slh_dsa *slh_dsa,
			      struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "FIPS205"));

	CKINT(acvp_req_set_prereq_slh_dsa(slh_dsa, NULL, entry, false));

	switch (slh_dsa->slh_dsa_mode) {
	case DEF_ALG_SLH_DSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));

		if (slh_dsa->capabilities_num != 1) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "SLH-DSA: KeyGen requires exactly one capability\n");
			ret = -EINVAL;
			goto out;
		}

		const struct def_algo_slh_dsa_caps *caps =
						slh_dsa->capabilities.keygen;
		CKINT(acvp_req_slh_dsa_parameter_set(caps->parameter_set,
						     entry));
		break;
	case DEF_ALG_SLH_DSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		CKINT(acvp_req_slh_dsa_siggen(slh_dsa, entry));
		break;
	case DEF_ALG_SLH_DSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		CKINT(acvp_req_slh_dsa_sigver(slh_dsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "SLH-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}
