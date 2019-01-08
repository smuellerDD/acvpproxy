/* JSON generator for EDDSA ciphers
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

static int acvp_req_eddsa_keygen(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	struct json_object *tmp;
	unsigned int found = 0;
	int ret;

	CKINT_LOG(acvp_req_cipher_to_array(entry, eddsa->curve,
					   ACVP_CIPHERTYPE_ECC, "curve"),
		  "Addition of curve specification failed\n");

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
	return acvp_req_cipher_to_array(entry, eddsa->curve,
					ACVP_CIPHERTYPE_ECC, "curve");
}


static int acvp_req_eddsa_siggen(const struct def_algo_eddsa *eddsa,
				 struct json_object *entry)
{
	int ret;
	bool boolean;

	CKINT_LOG(acvp_req_cipher_to_array(entry, eddsa->curve,
					   ACVP_CIPHERTYPE_ECC, "curve"),
		  "Addition of curve specification failed\n");

	switch(eddsa->eddsa_pure) {
	case DEF_ALG_EDDSA_PURE_SUPPORTED:
		boolean = true;
		break;
	case DEF_ALG_EDDSA_PURE_UNSUPPORTED:
		boolean = false;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Wrong value for eddsa_pure\n");
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
		       "Wrong value for eddsa_prehash\n");
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
	return acvp_req_eddsa_siggen(eddsa, entry);
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
int acvp_req_set_algo_eddsa(const struct def_algo_eddsa *eddsa,
			    struct json_object *entry)
{
	int ret = -EINVAL;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("EDDSA")));

	switch (eddsa->eddsa_mode) {
	case DEF_ALG_EDDSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		CKINT(acvp_req_eddsa_keygen(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_KEYVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyVer")));
		CKINT(acvp_req_eddsa_keyver(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		CKINT(acvp_req_eddsa_siggen(eddsa, entry));
		break;
	case DEF_ALG_EDDSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		CKINT(acvp_req_eddsa_sigver(eddsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown EDDSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT_LOG(acvp_req_gen_prereq(eddsa->prereqvals, eddsa->prereqvals_num,
				      entry), "Cannot add prerequisites\n");

	ret = 0;

out:
	return ret;
}
