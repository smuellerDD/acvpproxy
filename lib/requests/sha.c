/* JSON request generator for SHA-1, SHA-2, SHA-3
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_sha(const struct def_algo_sha *sha,
		       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	const char *name;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_req_cipher_to_name(sha->algorithm,
				      ACVP_CIPHERTYPE_HASH, &name));
	CKINT(acvp_duplicate(&tmp->cipher_name, name));

out:
	return ret;
}

/*
 * Generate algorithm entry for SHA hashes
 */
int acvp_req_set_algo_sha(const struct def_algo_sha *sha,
			  struct json_object *entry)
{
	int ret = 0;

	if (acvp_match_cipher(sha->algorithm, ACVP_SHA3_224) ||
	    acvp_match_cipher(sha->algorithm, ACVP_SHA3_256) ||
	    acvp_match_cipher(sha->algorithm, ACVP_SHA3_384) ||
	    acvp_match_cipher(sha->algorithm, ACVP_SHA3_512)) {
		CKINT(acvp_req_add_revision(entry, "2.0"));
	} else {
		CKINT(acvp_req_add_revision(entry, "1.0"));
	}

	CKINT(acvp_req_cipher_to_string(entry, sha->algorithm,
				        ACVP_CIPHERTYPE_HASH, "algorithm"));
	CKINT(json_object_object_add(entry, "inBit",
				     json_object_new_boolean(sha->inbit)));
	CKINT(json_object_object_add(entry, "inEmpty",
				     json_object_new_boolean(sha->inempty)));
	CKINT(acvp_req_algo_int_array(entry, sha->messagelength,
				      "messageLength"));
	CKINT(acvp_req_algo_int_array(entry, sha->largetest,
				      "performLargeDataTest"));

out:
	return ret;
}
