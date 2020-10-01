/* JSON request generator for SP800-90B conditioning components
 *
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_cond_comp(const struct def_algo_cond_comp *cond_comp,
			     struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	const char *mode;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_duplicate(&tmp->cipher_name, "ConditioningComponent"));
	CKINT(acvp_req_cipher_to_name(cond_comp->mode,
				      ACVP_CIPHERTYPE_COND, &mode));
	CKINT(acvp_duplicate(&tmp->cipher_mode, mode));

	if (cond_comp->mode & ACVP_COND_COMP_HASH_DF) {
		CKINT(acvp_req_cipher_to_stringarray(cond_comp->hashalg,
						     ACVP_CIPHERTYPE_HASH,
						     &tmp->cipher_aux));
	} else {
		CKINT(acvp_set_sym_keylen(tmp->keylen, cond_comp->keylen));
	}

	tmp->prereq_num = 0;

out:
	return ret;
}

int acvp_req_set_prereq_cond_comp(const struct def_algo_cond_comp *cond_comp,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool publish)
{
	int ret;

	(void)cond_comp;
	(void)deps;
	(void)publish;

	CKINT(json_object_object_add(entry, "algorithm",
			json_object_new_string("ConditioningComponent")));
	//CKINT(acvp_req_gen_prereq(&cond_comp->prereqvals, 1, deps, entry,
	//			    publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for Conditioning Components
 */
int acvp_req_set_algo_cond_comp(const struct def_algo_cond_comp *cond_comp,
				struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "SP800-90B"));

	CKINT(acvp_req_set_prereq_cond_comp(cond_comp, NULL, entry, false));

	CKINT(acvp_req_cipher_to_string(entry, cond_comp->mode,
					ACVP_CIPHERTYPE_COND, "mode"));

	if (cond_comp->mode & ACVP_COND_COMP_HASH_DF) {
		struct json_object * cap = json_object_new_array();
		struct json_object *new;

		CKNULL(cap, -ENOMEM);
		CKINT(json_object_object_add(entry, "capabilities", cap));

		new = json_object_new_object();
		CKNULL(new, -ENOMEM);
		CKINT(json_object_array_add(cap, new));

		CKINT(acvp_req_cipher_to_array(new, cond_comp->hashalg,
					       ACVP_CIPHERTYPE_HASH,
					       "hashAlg"));
		CKINT(acvp_req_algo_int_array(new, cond_comp->derived_len,
					      "payloadLen"));
	} else {
		CKINT(acvp_req_sym_keylen(entry, cond_comp->keylen));
		CKINT(acvp_req_algo_int_array(entry, cond_comp->derived_len,
				      "payloadLen"));
	}

out:
	return ret;
}
