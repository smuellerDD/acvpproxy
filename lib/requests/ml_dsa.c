/* JSON request generator for ML-DSA
 *
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

int acvp_list_algo_ml_dsa(const struct def_algo_ml_dsa *ml_dsa,
			  struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	unsigned int idx = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "ML-DSA"));
	switch (ml_dsa->ml_dsa_mode) {
	case DEF_ALG_ML_DSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_ML_DSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	case DEF_ALG_ML_DSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ML-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_44) {
		tmp->keylen[idx++] = 44;
	}
	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_65) {
		tmp->keylen[idx++] = 65;
	}
	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_87) {
		tmp->keylen[idx++] = 87;
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

/*
 * Generate algorithm entry for ML-DSA
 */
int acvp_req_set_algo_ml_dsa(const struct def_algo_ml_dsa *ml_dsa,
			     struct json_object *entry)
{
	struct json_object *array;
	int ret;

	CKINT(acvp_req_add_revision(entry, "FIPS204"));

	CKINT(acvp_req_set_prereq_ml_dsa(ml_dsa, NULL, entry, false));

	switch (ml_dsa->ml_dsa_mode) {
	case DEF_ALG_ML_DSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		break;
	case DEF_ALG_ML_DSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));

		CKINT(acvp_req_algo_int_array(entry, ml_dsa->messagelength,
					      "messageLength"));
		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "deterministic", array));
		if (ml_dsa->deterministic &
		    DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC) {
			CKINT(json_object_array_add(
				array, json_object_new_boolean(false)));
		}
		if (ml_dsa->deterministic &
		    DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC) {
			CKINT(json_object_array_add(
				array, json_object_new_boolean(true)));
		}
		break;
	case DEF_ALG_ML_DSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ML-DSA: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
	}

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSets", array));
	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_44) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-DSA-44")));
	}
	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_65) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-DSA-65")));
	}
	if (ml_dsa->parameter_set & DEF_ALG_ML_DSA_87) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-DSA-87")));
	}

out:
	return ret;
}
