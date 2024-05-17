/* JSON request generator for ML-KEM
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_ml_kem(const struct def_algo_ml_kem *ml_kem,
			struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	unsigned int idx = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_512) {
		tmp->keylen[idx++] = 512;
	}
	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_768) {
		tmp->keylen[idx++] = 65;
	}
	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_1024) {
		tmp->keylen[idx++] = 1024;
	}

	CKINT(acvp_duplicate(&tmp->cipher_name, "ML-KEM"));

out:
	return ret;
}

int acvp_req_set_prereq_ml_kem(const struct def_algo_ml_kem *ml_kem,
			     const struct acvp_test_deps *deps,
			     struct json_object *entry, bool publish)
{

#if 0
	int ret;

	CKINT(acvp_req_gen_prereq(&ml_kem->prereqvals, 1, deps, entry, publish));

out:
	return ret;
#else
	(void)ml_kem;
	(void)deps;
	(void)publish;
	json_object_object_add(entry, "algorithm",
			       json_object_new_string("ML-KEM"));
	return 0;
#endif
}

/*
 * Generate algorithm entry for HMACs
 */
int acvp_req_set_algo_ml_kem(const struct def_algo_ml_kem *ml_kem,
			   struct json_object *entry)
{
	struct json_object *array;
	int ret;

	CKINT(acvp_req_add_revision(entry, "FIPS203"));

	CKINT(acvp_req_set_prereq_ml_kem(ml_kem, NULL, entry, false));

	switch (ml_kem->ml_kem_mode) {
	case DEF_ALG_ML_KEM_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		break;
	case DEF_ALG_ML_KEM_MODE_ENCAPSULATION:
		CKINT(json_object_object_add(
			entry, "mode", json_object_new_string("encapDecap")));

		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "functions", array));
		CKINT(json_object_array_add(
			array, json_object_new_string("encapsulation")));
		break;
	case DEF_ALG_ML_KEM_MODE_DECAPSULATION:
		CKINT(json_object_object_add(
			entry, "mode", json_object_new_string("encapDecap")));

		array = json_object_new_array();
		CKNULL(array, -ENOMEM);
		CKINT(json_object_object_add(entry, "functions", array));
		CKINT(json_object_array_add(
			array, json_object_new_string("decapsulation")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ML-KEM: Unknown cipher type\n");
		ret = -EINVAL;
		goto out;
	}

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSets", array));
	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_512) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-KEM-512")));
	}
	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_768) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-KEM-768")));
	}
	if (ml_kem->parameter_set & DEF_ALG_ML_KEM_1024) {
		CKINT(json_object_array_add(
			array, json_object_new_string("ML-KEM-1024")));
	}

out:
	return ret;
}
