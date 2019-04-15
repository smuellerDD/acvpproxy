/* JSON request generator for CMAC
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

	CKINT(acvp_req_cipher_to_string(entry, cmac->algorithm,
					ACVP_CIPHERTYPE_MAC, "algorithm"));
	CKINT(acvp_req_gen_prereq(&cmac->prereqvals, 1, entry));

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

	CKINT(acvp_req_algo_int_array(caps, cmac->msglen, "msgLen"));

	/*
	 * Not configurable as truncated hashes are not seen in the wild
	 */
	if (acvp_match_cipher(cmac->algorithm, ACVP_CMAC_TDES))
		maclen = 64;
	else if (acvp_match_cipher(cmac->algorithm, ACVP_CMAC_AES))
		maclen = 128;
	else {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Cannot determine mac length for keyed message digest %s\n",
		       cmac->algorithm);
		ret = -EINVAL;
		goto out;
	}
	/* This is a domain definition */
	CKINT(acvp_req_algo_int_array_len(caps, &maclen, 1, "macLen"));

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}
