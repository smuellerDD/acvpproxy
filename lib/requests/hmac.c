/* JSON request generator for HMAC
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_hmac(const struct def_algo_hmac *hmac,
			struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	const char *name;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_req_cipher_to_name(hmac->algorithm,
				      ACVP_CIPHERTYPE_MAC, &name));
	CKINT(acvp_duplicate(&tmp->cipher_name, name));
	tmp->prereqs = &hmac->prereqvals;
	tmp->prereq_num = 1;

out:
	return ret;
}

int acvp_req_set_prereq_hmac(const struct def_algo_hmac *hmac,
			     const struct acvp_test_deps *deps,
			     struct json_object *entry, bool publish)
{
	int ret;

	CKINT(acvp_req_cipher_to_string(entry, hmac->algorithm,
					ACVP_CIPHERTYPE_MAC, "algorithm"));
	CKINT(acvp_req_gen_prereq(&hmac->prereqvals, 1, deps, entry, publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for HMACs
 */
int acvp_req_set_algo_hmac(const struct def_algo_hmac *hmac,
			   struct json_object *entry)
{
	int maclen;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_hmac(hmac, NULL, entry, false));
	CKINT(acvp_req_algo_int_array(entry, hmac->keylen, "keyLen"));

	/*
	 * Allow unset maclen definitions - we take the default of the hash
	 * output size.
	 */
	if (hmac->maclen[0] == 0) {
		if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA1))
			maclen = 160;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_224))
			maclen = 224;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_256))
			maclen = 256;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_384))
			maclen = 384;
		else if (acvp_match_cipher(hmac->algorithm,
					   ACVP_HMACSHA2_512224))
			maclen = 224;
		else if (acvp_match_cipher(hmac->algorithm,
					   ACVP_HMACSHA2_512256))
			maclen = 256;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_512))
			maclen = 512;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_224))
			maclen = 224;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_256))
			maclen = 256;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_384))
			maclen = 384;
		else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_512))
			maclen = 512;
		else {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "HMAC: Cannot determine mac length for keyed message digest %" PRIu64 "\n",
			       hmac->algorithm);
			ret = -EINVAL;
			goto out;
		}

		/* This is a domain definition */
		CKINT(acvp_req_algo_int_array_len(entry, &maclen, 1, "macLen"));
	} else {
		CKINT(acvp_req_algo_int_array(entry, hmac->maclen, "macLen"));
	}

out:
	return ret;
}
