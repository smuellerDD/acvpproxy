/* JSON request generator for ML-DSA
 *
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

static int acvp_req_ml_dsa_parameter_set(unsigned int parameter_set,
					 struct json_object *entry)
{
	struct json_object *parameter_sets_array;
	int ret = 0;

	parameter_sets_array = json_object_new_array();
	CKNULL(parameter_sets_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSets",
				     parameter_sets_array));

	if (parameter_set & DEF_ALG_ML_DSA_44) {
		CKINT(json_object_array_add(
			parameter_sets_array,
			json_object_new_string("ML-DSA-44")));
	}
	if (parameter_set & DEF_ALG_ML_DSA_65) {
		CKINT(json_object_array_add(
			parameter_sets_array,
			json_object_new_string("ML-DSA-65")));
	}
	if (parameter_set & DEF_ALG_ML_DSA_87) {
		CKINT(json_object_array_add(
			parameter_sets_array,
			json_object_new_string("ML-DSA-87")));
	}

out:
	return ret;
}

int acvp_list_algo_ml_dsa(const struct def_algo_ml_dsa *ml_dsa,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	unsigned int i, idx = 0;
	unsigned int all_parameter_sets = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "ML-DSA"));
	switch (ml_dsa->ml_dsa_mode) {
	case DEF_ALG_ML_DSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		for (i = 0; i < ml_dsa->capabilities_num; i++) {
			const struct def_algo_ml_dsa_caps *caps =
					ml_dsa->capabilities.keygen + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	case DEF_ALG_ML_DSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		for (i = 0; i < ml_dsa->capabilities_num; i++) {
			const struct def_algo_ml_dsa_caps *caps =
					ml_dsa->capabilities.siggen + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	case DEF_ALG_ML_DSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		for (i = 0; i < ml_dsa->capabilities_num; i++) {
			const struct def_algo_ml_dsa_caps *caps =
					ml_dsa->capabilities.sigver + i;
			all_parameter_sets |= caps->parameter_set;
		}
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ML-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if (all_parameter_sets & DEF_ALG_ML_DSA_44) {
		tmp->keylen[idx++] = 128;
	}
	if (all_parameter_sets & DEF_ALG_ML_DSA_65) {
		tmp->keylen[idx++] = 192;
	}
	if (all_parameter_sets & DEF_ALG_ML_DSA_87) {
		tmp->keylen[idx++] = 256;
	}
	tmp->keylen[idx] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int acvp_req_set_prereq_ml_dsa(const struct def_algo_ml_dsa *ml_dsa,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
#if 0
	int ret;

	CKINT(acvp_req_gen_prereq(&ml_dsa->prereqvals, 1, deps, entry, publish));

out:
	return ret;
#else
	(void)ml_dsa;
	(void)deps;
	(void)publish;
	json_object_object_add(entry, "algorithm",
			       json_object_new_string("ML-DSA"));
	return 0;
#endif
}

static int acvp_req_ml_dsa_sig_caps(const struct def_algo_ml_dsa_caps *caps,
				     struct json_object *caps_entry)
{
	int ret = 0;

	CKINT(acvp_req_ml_dsa_parameter_set(caps->parameter_set, caps_entry));
	CKINT(acvp_req_algo_int_array(caps_entry, caps->messagelength,
				      "messageLength"));
	if (caps->hashalg) {
		CKINT(acvp_req_cipher_to_array(caps_entry,
			caps->hashalg, ACVP_CIPHERTYPE_HASH, "hashAlgs"));
	}

	CKINT(acvp_req_algo_int_array(caps_entry, caps->contextlength,
				      "contextLength"));

out:
	return ret;
}

static int acvp_req_ml_dsa_sig_interface(
	const struct def_algo_ml_dsa *ml_dsa, struct json_object *entry)
{
	struct json_object *array;
	unsigned int i;
	int ret;
	bool pure_found = false, prehash_found = false;

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "signatureInterfaces", array));
	if (ml_dsa->interface & DEF_ALG_ML_DSA_INTERFACE_EXTERNAL) {
		CKINT(json_object_array_add(
			array,
			json_object_new_string("external")));
	}
	if (ml_dsa->interface & DEF_ALG_ML_DSA_INTERFACE_INTERNAL) {
		CKINT(json_object_array_add(
			array,
			json_object_new_string("internal")));
	}

	if (ml_dsa->interface & DEF_ALG_ML_DSA_INTERFACE_INTERNAL) {
		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "externalMu", array));
		if (ml_dsa->external_mu == 0) {
			/* If nothing was specified, we assume not supported */
			CKINT(json_object_array_add(
				    array,
				    json_object_new_boolean(false)));
		}
		if (ml_dsa->external_mu & DEF_ALG_ML_DSA_INTERNAL_MU) {
			CKINT(json_object_array_add(
				    array,
				    json_object_new_boolean(false)));
		}
		if (ml_dsa->external_mu & DEF_ALG_ML_DSA_EXTERNAL_MU) {
			CKINT(json_object_array_add(
				    array,
				    json_object_new_boolean(true)));
		}
	}

	if (ml_dsa->interface & DEF_ALG_ML_DSA_INTERFACE_EXTERNAL) {
		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "preHash", array));
		for (i = 0; i < ml_dsa->capabilities_num; i++) {
			const struct def_algo_ml_dsa_caps *caps =
						ml_dsa->capabilities.siggen + i;

			if (caps->hashalg && !prehash_found) {
				CKINT(json_object_array_add(
					    array,
					    json_object_new_string("preHash")));
				prehash_found = true;
			} else if (!caps->hashalg && !pure_found) {
				CKINT(json_object_array_add(
					    array,
					    json_object_new_string("pure")));
				pure_found = true;
			}
		}
	}

out:
	return ret;
}

static int acvp_req_ml_dsa_siggen(const struct def_algo_ml_dsa *ml_dsa,
				   struct json_object *entry)
{
	struct json_object *array;
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	for (i = 0; i < ml_dsa->capabilities_num; i++) {
		const struct def_algo_ml_dsa_caps *caps =
						ml_dsa->capabilities.siggen + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_ml_dsa_sig_caps(caps, caps_entry));
	}

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "deterministic", array));
	if (ml_dsa->deterministic & DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC) {
		CKINT(json_object_array_add(array,
					    json_object_new_boolean(false)));
	}
	if (ml_dsa->deterministic & DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC) {
		CKINT(json_object_array_add(array,
					    json_object_new_boolean(true)));
	}

	CKINT(acvp_req_ml_dsa_sig_interface(ml_dsa, entry));

out:
	return ret;
}

static int acvp_req_ml_dsa_sigver(const struct def_algo_ml_dsa *ml_dsa,
				   struct json_object *entry)
{
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	for (i = 0; i < ml_dsa->capabilities_num; i++) {
		const struct def_algo_ml_dsa_caps *caps =
						ml_dsa->capabilities.sigver + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_ml_dsa_sig_caps(caps, caps_entry));
	}

	CKINT(acvp_req_ml_dsa_sig_interface(ml_dsa, entry));

out:
	return ret;
}

/*
 * Generate algorithm entry for ML-DSA
 */
int acvp_req_set_algo_ml_dsa(const struct def_algo_ml_dsa *ml_dsa,
			      struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "FIPS204"));

	CKINT(acvp_req_set_prereq_ml_dsa(ml_dsa, NULL, entry, false));

	switch (ml_dsa->ml_dsa_mode) {
	case DEF_ALG_ML_DSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));

		if (ml_dsa->capabilities_num != 1) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "ML-DSA: KeyGen requires exactly one capability\n");
			ret = -EINVAL;
			goto out;
		}

		const struct def_algo_ml_dsa_caps *caps =
						ml_dsa->capabilities.keygen;
		CKINT(acvp_req_ml_dsa_parameter_set(caps->parameter_set,
						     entry));
		break;
	case DEF_ALG_ML_DSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		CKINT(acvp_req_ml_dsa_siggen(ml_dsa, entry));
		break;
	case DEF_ALG_ML_DSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		CKINT(acvp_req_ml_dsa_sigver(ml_dsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ML-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}
