/* JSON request generator for HMAC
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
 * Generate algorithm entry for HMACs
 */
int acvp_req_set_algo_hmac(const struct def_algo_hmac *hmac,
			   struct json_object *entry)
{
	int maclen;
	int ret;

	CKINT(acvp_req_cipher_to_string(entry, hmac->algorithm,
					ACVP_CIPHERTYPE_MAC, "algorithm"));
	CKINT(acvp_req_gen_prereq(&hmac->prereqvals, 1, entry));
	CKINT(acvp_req_algo_int_array(entry, hmac->keylen, "keyLen"));

	/*
	 * Not configurable as truncated hashes are not seen in the wild
	 */
	if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA1))
		maclen = 160;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_224))
		maclen = 224;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_256))
		maclen = 256;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_384))
		maclen = 384;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_512224))
		maclen = 224;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_512256))
		maclen = 256;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA2_512))
		maclen = 512;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_224))
		maclen = 224;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_256))
		maclen = 256;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_384))
		maclen = 384;
	else if (acvp_match_cipher(hmac->algorithm, ACVP_HMACSHA3_512))
		maclen = 512;
	else {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Cannot determine mac length for keyed message digest %s\n",
		       hmac->algorithm);
		ret = -EINVAL;
		goto out;
	}

	/* This is a domain definition */
	CKINT(acvp_req_algo_int_array_len(entry, &maclen, 1, "macLen"));

out:
	return ret;
}
