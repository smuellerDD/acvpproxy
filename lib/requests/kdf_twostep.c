/* JSON request generator for KAS ECC rev 3 (SP800-56A rev. 3)
 *
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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

static int
_acvp_req_set_algo_kdf_twostep(const struct def_algo_kdf_twostep *kdf_twostep,
			       const struct acvp_test_deps *deps,
			       struct json_object *entry, bool full,
			       bool publish)
{
	int ret;

	CKINT(acvp_req_gen_prereq(kdf_twostep->prereqvals,
				  kdf_twostep->prereqvals_num, deps, entry,
				  publish));

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KDA")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("TwoStep")));

	switch (kdf_twostep->kdf_spec) {
	case DEF_ALG_KDF_SP800_56Crev1:
		CKINT(acvp_req_add_revision(entry, "Sp800-56Cr1"));
		break;
	case DEF_ALG_KDF_SP800_56Crev2:
		CKINT(acvp_req_add_revision(entry, "Sp800-56Cr2"));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "SP800-56C: Unknown KDF specification\n");
		return -EINVAL;
	}

	if (!full)
		goto out;

	CKINT(acvp_req_kas_kdf_twostep_def(kdf_twostep->twostep,
					   kdf_twostep->twostep_num,
					   kdf_twostep->length,
					   entry));

	if (kdf_twostep->length > 2048) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: KAS KDF length maximum is 1024 bits\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(json_object_object_add(entry, "l",
				json_object_new_int((int)kdf_twostep->length)));

	CKINT(acvp_req_algo_int_array(entry, kdf_twostep->zlen, "z"));

	if (kdf_twostep->kdf_spec == DEF_ALG_KDF_SP800_56Crev2) {
		CKINT(json_object_object_add(entry, "usesHybridSharedSecret",
		    json_object_new_boolean(kdf_twostep->hybrid_shared_secret)));

		if (kdf_twostep->hybrid_shared_secret) {
			CKINT(acvp_req_algo_int_array(entry,
						      kdf_twostep->tlen,
						      "auxSharedSecretLen"));
		}
	}

out:
	return ret;
}

int acvp_list_algo_kdf_twostep(const struct def_algo_kdf_twostep *kdf_twostep,
			       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "KDA Sp800-56Cr1"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "TwoStep"));

	tmp->prereqs = kdf_twostep->prereqvals;
	tmp->prereq_num = kdf_twostep->prereqvals_num;

	tmp->keylen[0] = kdf_twostep->length;
	tmp->keylen[1] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int
acvp_req_set_prereq_kdf_twostep(const struct def_algo_kdf_twostep *kdf_twostep,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kdf_twostep(kdf_twostep, deps, entry, false,
					      publish);
}

int
acvp_req_set_algo_kdf_twostep(const struct def_algo_kdf_twostep *kdf_twostep,
			      struct json_object *entry)
{
	return _acvp_req_set_algo_kdf_twostep(kdf_twostep, NULL, entry, true,
					      false);
}
