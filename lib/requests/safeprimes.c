/* JSON request generator for SP800-56A rev3 safe primes
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

int acvp_list_algo_safeprimes(const struct def_algo_safeprimes *safeprimes,
			      struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_duplicate(&tmp->cipher_name, "safePrimes"));
	tmp->prereqs = &safeprimes->prereqvals;
	tmp->prereq_num = 1;

	switch (safeprimes->safeprime_mode) {
	case DEF_ALG_SAFEPRIMES_KEYGENERATION:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_SAFEPRIMES_KEYVERIFICATION:
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyVer"));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Safe Primes: Unknown safeprimes key mode\n");
		return -EINVAL;
	}

out:
	return ret;
}

int acvp_req_set_prereq_safeprimes(const struct def_algo_safeprimes *safeprimes,
				   const struct acvp_test_deps *deps,
				   struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("safePrimes")));

	switch (safeprimes->safeprime_mode) {
	case DEF_ALG_SAFEPRIMES_KEYGENERATION:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		break;
	case DEF_ALG_SAFEPRIMES_KEYVERIFICATION:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyVer")));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Safe Primes: Unknown safeprimes key mode\n");
		return -EINVAL;
	}

	CKINT(acvp_req_gen_prereq(&safeprimes->prereqvals, 1, deps, entry,
				  publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for Safe Primes
 */
int acvp_req_set_algo_safeprimes(const struct def_algo_safeprimes *safeprimes,
				 struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_safeprimes(safeprimes, NULL, entry, false));

	CKINT(acvp_req_cipher_to_array(entry, safeprimes->safeprime_groups,
				       ACVP_CIPHERTYPE_DOMAIN,
				      "safePrimeGroups"));

out:
	return ret;
}
