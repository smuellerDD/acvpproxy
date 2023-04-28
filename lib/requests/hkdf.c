/* JSON request generator for SP800-56C HKDF
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

int acvp_req_set_prereq_hkdf(const struct def_algo_hkdf *hkdf,
			     const struct acvp_test_deps *deps,
			     struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KDA")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("HKDF")));

	CKINT(acvp_req_gen_prereq(hkdf->prereqvals,
				  hkdf->prereqvals_num, deps, entry,
				  publish));

out:
	return ret;
}

int acvp_list_algo_hkdf(const struct def_algo_hkdf *hkdf,
			struct acvp_list_ciphers **new)
{
	const struct def_algo_hkdf_cipher *cipher_spec = &hkdf->cipher_spec;
	struct acvp_list_ciphers *tmp = NULL;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "HKDF"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "SP800-56C"));
	CKINT(acvp_req_cipher_to_stringarray(cipher_spec->macalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = hkdf->prereqvals;
	tmp->prereq_num = hkdf->prereqvals_num;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

static int acvp_req_set_algo_hkdf_details(const struct def_algo_hkdf *hkdf,
					  struct json_object *entry)
{
	const struct def_algo_hkdf_cipher *cipher_spec = &hkdf->cipher_spec;
	int ret;

	CKINT(acvp_req_cipher_to_array(entry, cipher_spec->macalg,
				       ACVP_CIPHERTYPE_HASH, "hmacAlg"));

	CKINT(acvp_req_algo_int_array(entry, cipher_spec->z, "z"));

	if (cipher_spec->l > 2048) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "SP800-56C HKDF: z maximum value is 2048\n");
		ret = -EINVAL;
		goto out;
	}
	CKINT(json_object_object_add(entry, "l",
				     json_object_new_int((int)cipher_spec->l)));

	CKINT(acvp_req_kas_mac_salt(hkdf->mac_salt_method, hkdf->saltlen,
				    entry));

	CKINT(acvp_req_kas_kdf_fi(hkdf->fixed_info_pattern_type,
				  hkdf->literal,
				  hkdf->fixed_info_encoding,
				  "fixedInfoPattern", entry));

out:
	return ret;
}

/*
 * Generate algorithm entry for HKDF
 */
int acvp_req_set_algo_hkdf(const struct def_algo_hkdf *hkdf,
			   struct json_object *entry)
{
	int ret;

	//TODO 56Cr2 with multiExpansion testing missing

	CKINT(acvp_req_add_revision(entry, "Sp800-56Cr1"));

	CKINT(acvp_req_set_prereq_hkdf(hkdf, NULL, entry, false));

	CKINT(acvp_req_set_algo_hkdf_details(hkdf, entry));

out:
	return ret;
}
