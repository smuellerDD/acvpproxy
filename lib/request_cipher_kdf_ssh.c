/* JSON request generator for SP800-135 KDF SSH
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
 * Generate algorithm entry for KDF SSH
 */
int acvp_req_set_algo_kdf_ssh(const struct def_algo_kdf_ssh *kdf_ssh,
			      struct json_object *entry)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("ssh")));

	CKINT(acvp_req_gen_prereq(kdf_ssh->prereqvals, kdf_ssh->prereqvals_num,
				  entry));

	if (!(kdf_ssh->cipher & ACVP_AES128 || kdf_ssh->cipher & ACVP_AES192 ||
	      kdf_ssh->cipher & ACVP_AES256 || kdf_ssh->cipher & ACVP_TDES)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KDF SSH: only ACVP_AES128, ACVP_AES192, ACVP_AES256 and ACVP_TDES allowed for cipher definition\n");
		ret = -EINVAL;
		goto out;

	}
	CKINT(acvp_req_cipher_to_array(entry, kdf_ssh->cipher, 0, "cipher"));

	CKINT(acvp_req_cipher_to_array(entry, kdf_ssh->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}
