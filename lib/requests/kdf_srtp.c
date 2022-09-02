/* JSON request generator for KDF SRTP
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

int acvp_req_set_prereq_kdf_srtp(const struct def_algo_kdf_srtp *kdf_srtp,
				 const struct acvp_test_deps *deps,
				 struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("srtp")));

	CKINT(acvp_req_gen_prereq(&kdf_srtp->prereqvals, 1, deps, entry,
				  publish));

out:
	return ret;
}

int acvp_list_algo_kdf_srtp(const struct def_algo_kdf_srtp *kdf_srtp,
			    struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	unsigned int entry = 0;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "kdf-components"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "srtp"));
	tmp->prereqs = &kdf_srtp->prereqvals;
	tmp->prereq_num = 1;

	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_128)
		tmp->keylen[entry++] = 128;
	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_192)
		tmp->keylen[entry++] = 192;
	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_256)
		tmp->keylen[entry++] = 256;

	tmp->keylen[entry] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

/*
 * Generate algorithm entry for KDF SRTP
 */
int acvp_req_set_algo_kdf_srtp(const struct def_algo_kdf_srtp *kdf_srtp,
			       struct json_object *entry)
{
	struct json_object *array;
	int ret;
	bool found = false;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_kdf_srtp(kdf_srtp, NULL, entry, false));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "aesKeyLength", array));
	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_128) {
		CKINT(json_object_array_add(array, json_object_new_int(128)));
		found = true;
	}
	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_192) {
		CKINT(json_object_array_add(array, json_object_new_int(192)));
		found = true;
	}
	if (kdf_srtp->aes_key_length & DEF_ALG_KDF_SRTP_KEYLEN_256) {
		CKINT(json_object_array_add(array, json_object_new_int(256)));
		found = true;
	}

	CKNULL_LOG(found, -EINVAL, "aes_key_length contains wrong data\n");

	CKINT(json_object_object_add(entry, "supportsZeroKdr",
				     json_object_new_boolean(kdf_srtp->supports_zero_kdr)));

	CKINT(acvp_req_algo_int_array_len(entry, kdf_srtp->kdr_exponent, 25,
					  "kdrExponent"));

out:
	return ret;
}
