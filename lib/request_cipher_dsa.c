/* JSON generator for DSA ciphers
 *
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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
			       "L = 1024 only allowed for SigVer\n");
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
		logger(LOGGER_WARN, LOGGER_C_ANY, "Unknown DSA L definition\n");
		ret = -EINVAL;
		goto out;
	}

	switch (dsa->dsa_n) {
	case DEF_ALG_DSA_N_160:
		if (dsa->dsa_l != DEF_ALG_DSA_L_1024) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "N = 160 only allowed for L = 1024");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_object_add(entry, N,
					     json_object_new_int(160)));
		break;
	case DEF_ALG_DSA_N_224:
		if (dsa->dsa_l != DEF_ALG_DSA_L_2048) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "N = 224 only allowed for L = 2048");
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
		logger(LOGGER_WARN, LOGGER_C_ANY, "Unknown DSA N definition\n");
		ret = -EINVAL;
		goto out;
	}

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
		       "No gGen information provided\n");
		ret = -EINVAL;
		goto out;
	}

	if (acvp_match_cipher(dsa->hashalg, ACVP_SHA1) &&
	    (dsa->dsa_mode != DEF_ALG_DSA_MODE_PQGVER) &&
	    (dsa->dsa_mode != DEF_ALG_DSA_MODE_SIGVER)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "SHA-1 can only be used with PQGVer or SigVer\n");
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
int acvp_req_set_algo_dsa(const struct def_algo_dsa *dsa,
			  struct json_object *entry)
{
	struct json_object *algspecs, *caparray = NULL;
	int ret = 0;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("DSA")));

	caparray = json_object_new_array();
	CKNULL(caparray, -ENOMEM);
	algspecs = json_object_new_object();
	CKNULL(algspecs, -ENOMEM);
	CKINT(json_object_array_add(caparray, algspecs));

	switch (dsa->dsa_mode) {
	case DEF_ALG_DSA_MODE_PQGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("pqgGen")));
		CKINT(acvp_req_dsa_pqggen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_PQGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("pqgVer")));
		CKINT(acvp_req_dsa_pqgver(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		CKINT(acvp_req_dsa_keygen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		CKINT(acvp_req_dsa_siggen(dsa, algspecs));
		break;
	case DEF_ALG_DSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		CKINT(acvp_req_dsa_sigver(dsa, algspecs));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown DSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_gen_prereq(dsa->prereqvals, dsa->prereqvals_num,
				  entry));
	CKINT(json_object_object_add(entry, "capabilities", caparray));
	caparray = NULL;

out:
	if (caparray)
		json_object_put(caparray);
	return ret;
}
