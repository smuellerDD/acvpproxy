/* JSON request generator for ANSI X9.63 KDF
 *
 * Copyright (C) 2021 - 2022, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_ansi_x963(const struct def_algo_ansi_x963 *ansi_x963,
			     struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "kdf-components"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "ansix9.63"));
	CKINT(acvp_req_cipher_to_stringarray(ansi_x963->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = &ansi_x963->prereqvals;
	tmp->prereq_num = 1;
	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int acvp_req_set_prereq_ansi_x963(const struct def_algo_ansi_x963 *ansi_x963,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("ansix9.63")));

	CKINT(acvp_req_gen_prereq(&ansi_x963->prereqvals, 1, deps, entry,
				  publish));

out:
	return ret;
}

static int acvp_ansi_x963_fieldsize(int size)
{
	switch (size) {
	case 224:
	case 233:
	case 256:
	case 283:
	case 384:
	case 409:
	case 521:
	case 571:
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * Generate algorithm entry for ANSI X9.63
 */
int acvp_req_set_algo_ansi_x963(const struct def_algo_ansi_x963 *ansi_x963,
				struct json_object *entry)
{
	struct json_object *tmp_array;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_ansi_x963(ansi_x963, NULL, entry, false));
	CKINT(acvp_req_algo_int_array(entry, ansi_x963->shared_info_len,
				      "sharedInfoLength"));

	CKINT_LOG(acvp_ansi_x963_fieldsize(ansi_x963->field_size[0]),
		  "ANSI X9.63: Minimum field size contains invalid entry\n");
	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "fieldSize", tmp_array));
	CKINT(json_object_array_add(tmp_array,
				json_object_new_int(ansi_x963->field_size[0])));

	if (ansi_x963->field_size[1]) {
		CKINT_LOG(acvp_ansi_x963_fieldsize(ansi_x963->field_size[1]),
			  "ANSI X9.63: Maximum field size contains invalid entry\n");
		CKINT(json_object_array_add(tmp_array,
				json_object_new_int(ansi_x963->field_size[1])));
	}

	CKINT(acvp_req_algo_int_array(entry, ansi_x963->key_data_len,
				      "keyDataLength"));

	if (!(ansi_x963->hashalg & ACVP_SHA224 ||
	      ansi_x963->hashalg & ACVP_SHA256 ||
	      ansi_x963->hashalg & ACVP_SHA384 ||
	      ansi_x963->hashalg & ACVP_SHA512)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ANSI X9.63: only ACVP_SHA224, ACVP_SHA256, ACVP_SHA384 and ACVP_SHA512 allowed for cipher definition\n");
	}

	CKINT(acvp_req_cipher_to_array(entry, ansi_x963->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}
