/* JSON request generator for CMAC
 *
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_cmac(const struct def_algo_cmac *cmac,
			struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	const char *name;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_req_cipher_to_name(cmac->algorithm,
				      ACVP_CIPHERTYPE_MAC, &name));
	CKINT(acvp_duplicate(&tmp->cipher_name, name));
	CKINT(acvp_set_sym_keylen(tmp->keylen, cmac->keylen));
	tmp->prereqs = &cmac->prereqvals;
	tmp->prereq_num = 1;

out:
	return ret;
}

int acvp_req_set_prereq_cmac(const struct def_algo_cmac *cmac,
			     const struct acvp_test_deps *deps,
			     struct json_object *entry, bool publish)
{
	int ret;

	CKINT(acvp_req_cipher_to_string(entry, cmac->algorithm,
					ACVP_CIPHERTYPE_MAC, "algorithm"));
	CKINT(acvp_req_gen_prereq(&cmac->prereqvals, 1, deps, entry, publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for CMACs
 */
int acvp_req_set_algo_cmac(const struct def_algo_cmac *cmac,
			   struct json_object *entry)
{
	struct json_object *tmp_array = NULL, *caps = NULL, *caps_array = NULL;
	int maclen;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_cmac(cmac, NULL, entry, false));

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	caps = json_object_new_object();
	CKNULL(caps, -ENOMEM);
	CKINT(json_object_array_add(caps_array, caps));

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	if (cmac->direction & DEF_ALG_CMAC_GENERATION)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_string("gen")));
	if (cmac->direction & DEF_ALG_CMAC_VERIFICATION)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_string("ver")));
	CKINT(json_object_object_add(caps, "direction", tmp_array));
	tmp_array = NULL;

	CKINT(acvp_req_sym_keylen(caps, cmac->keylen));

	CKINT(acvp_req_tdes_keyopt(caps, cmac->algorithm));

	CKINT_LOG(acvp_req_valid_range(0, 524288, 8, cmac->msglen),
		  "CMAC: message length is outside of allowed range (0 - 524288)\n");
	CKINT(acvp_req_algo_int_array(caps, cmac->msglen, "msgLen"));

	/*
	 * Allow unset maclen definitions - we take the default of the block
	 * size of the symmetric cipher.
	 */
	if (cmac->maclen[0] == 0) {
		if (acvp_match_cipher(cmac->algorithm, ACVP_CMAC_TDES))
			maclen = 64;
		else if (acvp_match_cipher(cmac->algorithm, ACVP_CMAC_AES))
			maclen = 128;
		else {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "CMAC: Cannot determine mac length for keyed message digest %" PRIu64 "\n",
			       cmac->algorithm);
			ret = -EINVAL;
			goto out;
		}
		/* This is a domain definition */
		CKINT_LOG(acvp_req_valid_range_one(32, 128, 8, maclen),
			"CMAC: MAC length is outside of allowed range (32 - 128)\n");
		CKINT(acvp_req_algo_int_array_len(caps, &maclen, 1, "macLen"));
	} else {
		CKINT(acvp_req_algo_int_array(caps, cmac->maclen, "macLen"));
	}

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}
