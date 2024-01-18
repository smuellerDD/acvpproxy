/* JSON generator for ECDSA ciphers
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

static int acvp_req_ecdsa_keygen(const struct def_algo_ecdsa *ecdsa,
				 struct json_object *entry)
{
	struct json_object *tmp;
	unsigned int found = 0;
	int ret;

	if (ecdsa->revision == DEF_ALG_ECDSA_186_5) {
		CKINT(acvp_req_add_revision(entry, "FIPS186-5"));
	} else {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(acvp_req_cipher_to_array(entry, ecdsa->curve,
				       ACVP_CIPHERTYPE_ECC, "curve"));

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "secretGenerationMode", tmp));
	if (ecdsa->secretgenerationmode & DEF_ALG_ECDSA_EXTRA_BITS) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("extra bits")));
		found = 1;
	}
	if (ecdsa->secretgenerationmode & DEF_ALG_ECDSA_TESTING_CANDIDATES) {
		CKINT(json_object_array_add(tmp,
				json_object_new_string("testing candidates")));
		found = 1;
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ECDSA: SecretGenerationMode not defined\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int acvp_req_ecdsa_keyver(const struct def_algo_ecdsa *ecdsa,
				 struct json_object *entry)
{
	int ret;


	if (ecdsa->revision == DEF_ALG_ECDSA_186_5) {
		CKINT(acvp_req_add_revision(entry, "FIPS186-5"));
	} else {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(acvp_req_cipher_to_array(entry, ecdsa->curve,
				       ACVP_CIPHERTYPE_ECC, "curve"));

out:
	return ret;
}

static int acvp_req_ecdsa_sig_helper(const struct def_algo_ecdsa *ecdsa,
				     struct json_object *entry)
{
	struct json_object *tmp, *cap_array;
	int ret;

	cap_array = json_object_new_array();
	CKNULL(cap_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", cap_array));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_array_add(cap_array, tmp));
	CKINT(acvp_req_cipher_to_array(tmp, ecdsa->curve,
				       ACVP_CIPHERTYPE_ECC, "curve"));

	CKINT(acvp_req_cipher_to_array(tmp, ecdsa->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}

static int acvp_req_ecdsa_siggen(const struct def_algo_ecdsa *ecdsa,
				 struct json_object *entry)
{
	int ret;

	if (ecdsa->revision == DEF_ALG_ECDSA_186_5) {
		CKINT(acvp_req_add_revision(entry, "FIPS186-5"));
	} else {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(json_object_object_add(entry, "componentTest",
			json_object_new_boolean(ecdsa->component_test)));

	CKINT(acvp_req_ecdsa_sig_helper(ecdsa, entry));

out:
	return ret;
}

static int acvp_req_ecdsa_sigver(const struct def_algo_ecdsa *ecdsa,
				 struct json_object *entry)
{
	int ret;

	if (ecdsa->revision == DEF_ALG_ECDSA_186_5) {
		CKINT(acvp_req_add_revision(entry, "FIPS186-5"));
	} else {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(json_object_object_add(entry, "componentTest",
			json_object_new_boolean(ecdsa->component_test)));

	CKINT(acvp_req_ecdsa_sig_helper(ecdsa, entry));

out:
	return ret;
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
static int _acvp_req_set_algo_ecdsa(const struct def_algo_ecdsa *ecdsa,
				    const struct acvp_test_deps *deps,
				    struct json_object *entry, bool full,
				    bool publish)
{
	int ret = -EINVAL;

	switch (ecdsa->ecdsa_mode) {
	case DEF_ALG_ECDSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("ECDSA")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		if (full)
			CKINT(acvp_req_ecdsa_keygen(ecdsa, entry));
		break;
	case DEF_ALG_ECDSA_MODE_KEYVER:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("ECDSA")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyVer")));
		if (full)
			CKINT(acvp_req_ecdsa_keyver(ecdsa, entry));
		break;
	case DEF_ALG_ECDSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("ECDSA")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		if (full)
			CKINT(acvp_req_ecdsa_siggen(ecdsa, entry));
		break;
	case DEF_ALG_ECDSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("ECDSA")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		if (full)
			CKINT(acvp_req_ecdsa_sigver(ecdsa, entry));
		break;
	case DEF_ALG_ECDSA_MODE_DETERMINISTIC_SIGGEN:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("DetECDSA")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		if (full)
			CKINT(acvp_req_ecdsa_siggen(ecdsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ECDSA: Unknown ECDSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_gen_prereq(ecdsa->prereqvals, ecdsa->prereqvals_num,
				  deps, entry, publish));

	ret = 0;

out:
	return ret;
}

int acvp_list_algo_ecdsa(const struct def_algo_ecdsa *ecdsa,
			 struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_req_cipher_to_intarray(ecdsa->curve, ACVP_CIPHERTYPE_ECC,
					  tmp->keylen));
	CKINT(acvp_req_cipher_to_stringarray(ecdsa->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = ecdsa->prereqvals;
	tmp->prereq_num = ecdsa->prereqvals_num;

	switch (ecdsa->ecdsa_mode) {
	case DEF_ALG_ECDSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_name, "ECDSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_ECDSA_MODE_KEYVER:
		CKINT(acvp_duplicate(&tmp->cipher_name, "ECDSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyVer"));
		break;
	case DEF_ALG_ECDSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_name, "ECDSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	case DEF_ALG_ECDSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_name, "ECDSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		break;
	case DEF_ALG_ECDSA_MODE_DETERMINISTIC_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_name, "DetECDSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ECDSA: Unknown ECDSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

out:
	return ret;
}

int acvp_req_set_prereq_ecdsa(const struct def_algo_ecdsa *ecdsa,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_ecdsa(ecdsa, deps, entry, false, publish);
}

int acvp_req_set_algo_ecdsa(const struct def_algo_ecdsa *ecdsa,
			    struct json_object *entry)
{
	return _acvp_req_set_algo_ecdsa(ecdsa, NULL, entry, true, false);
}
