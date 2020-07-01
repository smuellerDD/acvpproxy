/* JSON request generator for SP800-132 PBKDF
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

int acvp_req_set_prereq_pbkdf(const struct def_algo_pbkdf *pbkdf,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("PBKDF")));

	CKINT(acvp_req_gen_prereq(pbkdf->prereqvals,
				  pbkdf->prereqvals_num, deps, entry, publish));

out:
	return ret;
}

int acvp_list_algo_pbkdf(const struct def_algo_pbkdf *pbkdf,
			 struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret;

	(void)pbkdf;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "kdf-components"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "pbkdf"));
	CKINT(acvp_req_cipher_to_stringarray(pbkdf->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = pbkdf->prereqvals;
	tmp->prereq_num = pbkdf->prereqvals_num;
	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

/*
 * Generate algorithm entry for PBKDF
 */
int acvp_req_set_algo_pbkdf(const struct def_algo_pbkdf *pbkdf,
			    struct json_object *entry)
{
	struct json_object *caps_array, *one_entry;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_pbkdf(pbkdf, NULL, entry, false));

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", caps_array));

	one_entry = json_object_new_object();
	CKNULL(one_entry, -ENOMEM);
	CKINT(json_object_array_add(caps_array, one_entry));

	CKINT(acvp_req_algo_int_array(one_entry, pbkdf->iteration_count,
				      "iterationCount"));

	CKINT(acvp_req_algo_int_array(one_entry, pbkdf->keylen, "keyLen"));

	CKINT(acvp_req_algo_int_array(one_entry, pbkdf->passwordlen,
				      "passwordLen"));

	CKINT(acvp_req_algo_int_array(one_entry, pbkdf->saltlen, "saltLen"));

	CKINT(acvp_req_cipher_to_array(one_entry, pbkdf->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hmacAlg"));

out:
	return ret;
}
