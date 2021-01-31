/* JSON generator for EDDSA ciphers
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

static int acvp_req_eddsa_keygen(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	struct json_object *tmp;
	unsigned int found = 0;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT_LOG(acvp_req_cipher_to_array(entry, eddsa->curve,
					   ACVP_CIPHERTYPE_ECC, "curve"),
		  "EDDSA: Addition of curve specification failed\n");

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "secretGenerationMode", tmp));
	if (eddsa->secretgenerationmode & DEF_ALG_EDDSA_EXTRA_BITS) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("extra bits")));
		found = 1;
	}
	if (eddsa->secretgenerationmode & DEF_ALG_EDDSA_TESTING_CANDIDATES) {
		CKINT(json_object_array_add(tmp,
				json_object_new_string("testing candidates")));
		found = 1;
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "EDDSA: SecretGenerationMode not defined\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int acvp_req_eddsa_keyver(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));
	CKINT(acvp_req_cipher_to_array(entry, eddsa->curve,
				       ACVP_CIPHERTYPE_ECC, "curve"));

out:
	return ret;
}

static int acvp_req_eddsa_siggen(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	int ret;
	bool boolean;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT_LOG(acvp_req_cipher_to_array(entry, eddsa->curve,
					   ACVP_CIPHERTYPE_ECC, "curve"),
		  "EDDSA: Addition of curve specification failed\n");

	switch(eddsa->eddsa_pure) {
	case DEF_ALG_EDDSA_PURE_SUPPORTED:
		boolean = true;
		break;
	case DEF_ALG_EDDSA_PURE_UNSUPPORTED:
		boolean = false;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "EDDSA: Wrong value for eddsa_pure\n");
		return -EINVAL;
	}
	CKINT(json_object_object_add(entry, "pure",
				     json_object_new_boolean(boolean)));

	switch(eddsa->eddsa_prehash) {
	case DEF_ALG_EDDSA_PREHASH_SUPPORTED:
		boolean = true;
		break;
	case DEF_ALG_EDDSA_PREHASH_UNSUPPORTED:
		boolean = false;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "EDDSA: Wrong value for eddsa_prehash\n");
		return -EINVAL;
	}
	CKINT(json_object_object_add(entry, "preHash",
				     json_object_new_boolean(boolean)));

out:
	return ret;
}

static int acvp_req_eddsa_sigver(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));
	CKINT(acvp_req_eddsa_siggen(eddsa, entry));

out:
	return ret;
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
static int _acvp_req_set_algo_eddsa(const struct def_algo_eddsa *eddsa,
				    const struct acvp_test_deps *deps,
				    struct json_object *entry, bool full,
				    bool publish)
{
	int ret = -EINVAL;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("EDDSA")));

	switch (eddsa->eddsa_mode) {
	case DEF_ALG_EDDSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		if (full)
			CKINT(acvp_req_eddsa_keygen(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_KEYVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyVer")));
		if (full)
			CKINT(acvp_req_eddsa_keyver(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		if (full)
			CKINT(acvp_req_eddsa_siggen(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		if (full)
			CKINT(acvp_req_eddsa_sigver(eddsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "EDDSA: Unknown EDDSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT_LOG(acvp_req_gen_prereq(eddsa->prereqvals, eddsa->prereqvals_num,
				      deps, entry, publish),
		  "EDDSA: Cannot add prerequisites\n");

	ret = 0;

out:
	return ret;
}

int acvp_list_algo_eddsa(const struct def_algo_eddsa *eddsa,
			 struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "EDDSA"));

	CKINT(acvp_req_cipher_to_intarray(eddsa->curve, ACVP_CIPHERTYPE_ECC,
					  tmp->keylen));
	tmp->prereqs = eddsa->prereqvals;
	tmp->prereq_num = eddsa->prereqvals_num;

	switch (eddsa->eddsa_mode) {
	case DEF_ALG_EDDSA_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_EDDSA_MODE_KEYVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyVer"));
		break;
	case DEF_ALG_EDDSA_MODE_SIGGEN:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigGen"));
		break;
	case DEF_ALG_EDDSA_MODE_SIGVER:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "sigVer"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "EDDSA: Unknown EDDSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

out:
	return ret;
}

int acvp_req_set_prereq_eddsa(const struct def_algo_eddsa *eddsa,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_eddsa(eddsa, deps, entry, false, publish);
}

int acvp_req_set_algo_eddsa(const struct def_algo_eddsa *eddsa,
			    struct json_object *entry)
{
	return _acvp_req_set_algo_eddsa(eddsa, NULL, entry, true, false);
}
