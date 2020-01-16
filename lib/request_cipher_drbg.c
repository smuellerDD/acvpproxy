/* JSON request generator for SP800-90A DRBG
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

int acvp_req_set_prereq_drbg(const struct def_algo_drbg *drbg,
			     struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string(drbg->algorithm)));

	CKINT(acvp_req_gen_prereq(drbg->prereqvals, drbg->prereqvals_num,
				  entry, publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for DRBG
 */
int acvp_req_set_algo_drbg(const struct def_algo_drbg *drbg,
			   struct json_object *entry)
{
	const struct def_algo_drbg_caps *caps = drbg->capabilities;
	struct json_object *tmp_array = NULL;
	unsigned int i;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_drbg(drbg, entry, false));

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	if (drbg->pr & DEF_ALG_DRBG_PR_DISABLED)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(false)));
	if (drbg->pr & DEF_ALG_DRBG_PR_ENABLED)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(true)));
	CKINT(json_object_object_add(entry, "predResistanceEnabled",
				     tmp_array));

	CKINT(json_object_object_add(entry, "reseedImplemented",
				     json_object_new_boolean(drbg->reseed)));

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	for (i = 0; i < drbg->num_caps; i++) {
		struct json_object *cap_entry = json_object_new_object();

		CKNULL(cap_entry, -ENOMEM);

		CKINT(acvp_req_cipher_to_string(cap_entry, caps->mode,
						ACVP_CIPHERTYPE_HASH |
						ACVP_CIPHERTYPE_AES,
						"mode"));

		CKINT(json_object_object_add(cap_entry, "derFuncEnabled",
					json_object_new_boolean(caps->df)));

		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->entropyinputlen,
						     "entropyInputLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->noncelen,
						     "nonceLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->persostringlen,
						     "persoStringLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->additionalinputlen,
						     "additionalInputLen"));

		CKINT(json_object_object_add(cap_entry, "returnedBitsLen",
			       json_object_new_int(caps->returnedbitslen)));

		CKINT(json_object_array_add(tmp_array, cap_entry));

		caps++;
	}

	CKINT(json_object_object_add(entry, "capabilities", tmp_array));
	tmp_array = NULL;

	ret = 0;

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}
