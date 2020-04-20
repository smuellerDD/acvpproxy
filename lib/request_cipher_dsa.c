/* JSON generator for DSA ciphers
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#define L	"l"
#define N	"n"

static int acvp_req_dsa_l_n(const struct def_algo_dsa *dsa,
			    struct json_object *entry)
{
	int ret = 0;

	switch(dsa->dsa_l) {
	case DEF_ALG_DSA_L_1024:
		if (dsa->dsa_mode != DEF_ALG_DSA_MODE_SIGVER &&
		    dsa->dsa_mode != DEF_ALG_DSA_MODE_PQGVER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "DSA: L = 1024 only allowed for SigVer\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_object_add(entry, L,
					     json_object_new_int(1024)));
		break;
	case DEF_ALG_DSA_L_2048:
		CKINT(json_object_object_add(entry, L,
					     json_object_new_int(2048)));
		break;
	case DEF_ALG_DSA_L_3072:
		CKINT(json_object_object_add(entry, L,
					     json_object_new_int(3072)));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: Unknown DSA L definition\n");
		ret = -EINVAL;
		goto out;
	}

	switch (dsa->dsa_n) {
	case DEF_ALG_DSA_N_160:
		if (dsa->dsa_l != DEF_ALG_DSA_L_1024) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "DSA: N = 160 only allowed for L = 1024");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_object_add(entry, N,
					     json_object_new_int(160)));
		break;
	case DEF_ALG_DSA_N_224:
		if (dsa->dsa_l != DEF_ALG_DSA_L_2048) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "DSA: N = 224 only allowed for L = 2048");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_object_add(entry, N,
					     json_object_new_int(224)));
		break;
	case DEF_ALG_DSA_N_256:
		CKINT(json_object_object_add(entry, N,
					     json_object_new_int(256)));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: Unknown DSA N definition\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int acvp_list_dsa_n(const struct def_algo_dsa *dsa,
			   cipher_t keylen[DEF_ALG_MAX_INT], unsigned int *idx)
{
	if (dsa->dsa_n == DEF_ALG_DSA_N_160) {
		keylen[*idx] = 160;
		*idx += 1;
		if (*idx >= DEF_ALG_MAX_INT)
			return 0;
	}
	if (dsa->dsa_n == DEF_ALG_DSA_N_224) {
		keylen[*idx] = 224;
		*idx += 1;
		if (*idx >= DEF_ALG_MAX_INT)
			return 0;
	}
	if (dsa->dsa_n == DEF_ALG_DSA_N_256) {
		keylen[*idx] = 256;
		*idx += 1;
		if (*idx >= DEF_ALG_MAX_INT)
			return 0;
	}

	return 0;
}

static int acvp_list_dsa_l_n(const struct def_algo_dsa *dsa,
			     cipher_t keylen[DEF_ALG_MAX_INT])
{
	unsigned int idx = 0;
	int ret = 0;

	if (dsa->dsa_l == DEF_ALG_DSA_L_1024) {
		keylen[idx++] = 1024;
		CKINT(acvp_list_dsa_n(dsa, keylen, &idx));
		if (idx >= DEF_ALG_MAX_INT)
			goto out;
	}
	if (dsa->dsa_l == DEF_ALG_DSA_L_2048) {
		keylen[idx++] = 2048;
		CKINT(acvp_list_dsa_n(dsa, keylen, &idx));
		if (idx >= DEF_ALG_MAX_INT)
			goto out;
	}
	if (dsa->dsa_l == DEF_ALG_DSA_L_3072) {
		keylen[idx++] = 3072;
		CKINT(acvp_list_dsa_n(dsa, keylen, &idx));
		if (idx >= DEF_ALG_MAX_INT)
			goto out;
	}

	if (idx < DEF_ALG_MAX_INT)
		keylen[idx] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

static int acvp_req_dsa_pqggen(const struct def_algo_dsa *dsa,
			       struct json_object *entry)
{
	struct json_object *array;
	int ret, found = 0;

	CKINT(acvp_req_dsa_l_n(dsa, entry));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "pqGen", array));
	if (dsa->dsa_pq_gen_method & DEF_ALG_DSA_PROBABLE_PQ_GEN) {
		CKINT(json_object_array_add(array,
					json_object_new_string("probable")));
		found = 1;
	}
	if (dsa->dsa_pq_gen_method == DEF_ALG_DSA_PROVABLE_PQ_GEN) {
		CKINT(json_object_array_add(array,
					json_object_new_string("provable")));
		found = 1;
	}
	if (!found) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "No pqGen information provided\n");
		ret = -EINVAL;
		goto out;
	}

	found = 0;
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "gGen", array));
	if (dsa->dsa_g_gen_method & DEF_ALG_DSA_CANONICAL_G_GEN) {
		CKINT(json_object_array_add(array,
					json_object_new_string("canonical")));
		found = 1;
	}
	if (dsa->dsa_g_gen_method == DEF_ALG_DSA_UNVERIFIABLE_G_GEN) {
		CKINT(json_object_array_add(array,
				json_object_new_string("unverifiable")));
		found = 1;
	}
	if (!found) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: No gGen information provided\n");
		ret = -EINVAL;
		goto out;
	}

	if (acvp_match_cipher(dsa->hashalg, ACVP_SHA1) &&
	    (dsa->dsa_mode != DEF_ALG_DSA_MODE_PQGVER) &&
	    (dsa->dsa_mode != DEF_ALG_DSA_MODE_SIGVER)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: SHA-1 can only be used with PQGVer or SigVer\n");
		ret = -EINVAL;
		goto out;
	}
	CKINT(acvp_req_cipher_to_array(entry, dsa->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}

static int acvp_req_dsa_pqgver(const struct def_algo_dsa *dsa,
			       struct json_object *entry)
{
	return acvp_req_dsa_pqggen(dsa, entry);
}

static int acvp_req_dsa_keygen(const struct def_algo_dsa *dsa,
			       struct json_object *entry)
{
	return acvp_req_dsa_l_n(dsa, entry);
}

static int acvp_req_dsa_siggen(const struct def_algo_dsa *dsa,
			       struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_dsa_l_n(dsa, entry));
	CKINT(acvp_req_cipher_to_array(entry, dsa->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}

static int acvp_req_dsa_sigver(const struct def_algo_dsa *dsa,
			       struct json_object *entry)
{
	return acvp_req_dsa_siggen(dsa, entry);
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
static int _acvp_req_set_algo_dsa(const struct def_algo_dsa *dsa,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool full,
				  bool publish)
{
	struct json_object *algspecs = NULL, *caparray = NULL;
	int ret = 0;

	if (full) {
		CKINT(acvp_req_add_revision(entry, "1.0"));

		caparray = json_object_new_array();
		CKNULL(caparray, -ENOMEM);

		algspecs = json_object_new_object();
		CKNULL(algspecs, -ENOMEM);
		CKINT(json_object_array_add(caparray, algspecs));

		CKINT(json_object_object_add(entry, "capabilities", caparray));
		caparray = NULL;
	}

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("DSA")));

	switch (dsa->dsa_mode) {
	case DEF_ALG_DSA_MODE_PQGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("pqgGen")));
		if (full)
			CKINT(acvp_req_dsa_pqggen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_PQGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("pqgVer")));
		if (full)
			CKINT(acvp_req_dsa_pqgver(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		if (full)
			CKINT(acvp_req_dsa_keygen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		if (full)
			CKINT(acvp_req_dsa_siggen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		if (full)
			CKINT(acvp_req_dsa_sigver(dsa, algspecs));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: Unknown DSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_gen_prereq(dsa->prereqvals, dsa->prereqvals_num, deps,
				  entry, publish));

out:
	if (caparray)
		json_object_put(caparray);
	return ret;
}

int acvp_list_algo_dsa(const struct def_algo_dsa *dsa,
		       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "DSA"));
	CKINT(acvp_list_dsa_l_n(dsa, tmp->keylen));
	tmp->prereqs = dsa->prereqvals;
	tmp->prereq_num = dsa->prereqvals_num;

	switch (dsa->dsa_mode) {
	case DEF_ALG_DSA_MODE_PQGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "pqgGen"));
		break;
	case DEF_ALG_DSA_MODE_PQGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "pqgVer"));
		break;
	case DEF_ALG_DSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_DSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	case DEF_ALG_DSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "DSA: Unknown DSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_cipher_to_stringarray(dsa->hashalg, ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));

out:
	return ret;
}

int acvp_req_set_prereq_dsa(const struct def_algo_dsa *dsa,
			    const struct acvp_test_deps *deps,
			    struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_dsa(dsa, deps, entry, false, publish);
}

int acvp_req_set_algo_dsa(const struct def_algo_dsa *dsa,
			  struct json_object *entry)
{
	return _acvp_req_set_algo_dsa(dsa, NULL, entry, true, false);
}
