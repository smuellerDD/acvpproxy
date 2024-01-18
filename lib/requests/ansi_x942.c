/* JSON request generator for ANSI X9.42 KDF
 *
 * Copyright (C) 2022 - 2022, Joachim Vandersmissen <joachim@atsec.com>
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

int acvp_list_algo_ansi_x942(const struct def_algo_ansi_x942 *ansi_x942,
			     struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	unsigned int entry = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "kdf-components"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "ansix9.42"));
	CKINT(acvp_req_cipher_to_stringarray(ansi_x942->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = &ansi_x942->prereqvals;
	tmp->prereq_num = 1;

	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_TDES)
		tmp->keylen[entry++] = 168;
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_128_KW)
		tmp->keylen[entry++] = 128;
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_192_KW)
		tmp->keylen[entry++] = 192;
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_256_KW)
		tmp->keylen[entry++] = 256;

	tmp->keylen[entry] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int acvp_req_set_prereq_ansi_x942(const struct def_algo_ansi_x942 *ansi_x942,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("ansix9.42")));

	CKINT(acvp_req_gen_prereq(&ansi_x942->prereqvals, 1, deps, entry,
				  publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for ANSI X9.42
 */
int acvp_req_set_algo_ansi_x942(const struct def_algo_ansi_x942 *ansi_x942,
				struct json_object *entry)
{
	struct json_object *array;
	int ret;
	bool found;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_ansi_x942(ansi_x942, NULL, entry, false));

	found = false;
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "kdfType", array));
	if (ansi_x942->kdf_type & DEF_ALG_ANSI_X942_KDF_DER) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("DER")));
		found = true;
	}
	if (ansi_x942->kdf_type & DEF_ALG_ANSI_X942_KDF_CONCATENATION) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("concatenation")));
		found = true;
	}

	CKNULL_LOG(found, -EINVAL, "kdf_type contains wrong data\n");

	CKINT(acvp_req_algo_int_array(entry, ansi_x942->key_len, "keyLen"));

	if (ansi_x942->kdf_type & DEF_ALG_ANSI_X942_KDF_CONCATENATION) {
		CKINT(acvp_req_algo_int_array(entry, ansi_x942->other_info_len,
					      "otherInfoLen"));
	}

	if (ansi_x942->kdf_type & DEF_ALG_ANSI_X942_KDF_DER) {
		CKINT(acvp_req_algo_int_array(entry, ansi_x942->supp_info_len,
					      "suppInfoLen"));
	}

	CKINT(acvp_req_algo_int_array(entry, ansi_x942->zz_len, "zzLen"));

	found = false;
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "oid", array));
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_TDES) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("TDES")));
		found = true;
	}
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_128_KW) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("AES-128-KW")));
		found = true;
	}
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_192_KW) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("AES-192-KW")));
		found = true;
	}
	if (ansi_x942->oid & DEF_ALG_ANSI_X942_OID_AES_256_KW) {
		CKINT(json_object_array_add(array,
					    json_object_new_string("AES-256-KW")));
		found = true;
	}

	CKNULL_LOG(found, -EINVAL, "oid contains wrong data\n");

	if (ansi_x942->hashalg & ~(ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |
	    ACVP_SHA384 | ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |
	    ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 | ACVP_SHA3_512)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ANSI X9.42: only ACVP_SHA1, ACVP_SHA2*, and ACVP_SHA3* allowed for cipher definition\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(acvp_req_cipher_to_array(entry, ansi_x942->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}
