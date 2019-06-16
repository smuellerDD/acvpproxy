/* JSON request generator for SP800-132 PBKDF
 *
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

/*
 * Generate algorithm entry for PBKDF
 */
int acvp_req_set_algo_pbkdf(const struct def_algo_pbkdf *pbkdf,
			    struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("pbkdf")));

	CKINT(acvp_req_gen_prereq(pbkdf->prereqvals,
				  pbkdf->prereqvals_num, entry));

	CKINT(acvp_req_algo_int_array(entry, pbkdf->iteration_count,
				      "iterationCount"));

	CKINT(acvp_req_algo_int_array(entry, pbkdf->keylen, "keyLen"));

	CKINT(acvp_req_algo_int_array(entry, pbkdf->passwordlen,
				      "passwordLen"));

	CKINT(acvp_req_algo_int_array(entry, pbkdf->saltlen, "saltLen"));

	CKINT(acvp_req_cipher_to_array(entry, pbkdf->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}
