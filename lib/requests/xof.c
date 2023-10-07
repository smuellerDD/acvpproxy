/* JSON request generator for SHAKE
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

int acvp_list_algo_xof(const struct def_algo_xof *xof,
		       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp;
	const char *name;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_req_cipher_to_name(xof->algorithm,
				      ACVP_CIPHERTYPE_HASH |
				      ACVP_CIPHERTYPE_MAC, &name));
	CKINT(acvp_duplicate(&tmp->cipher_name, name));

out:
	return ret;
}

int acvp_req_set_algo_xof(const struct def_algo_xof *xof,
			    struct json_object *entry)
{
	struct json_object *tmp_array = NULL;
	int ret;

	if ((xof->algorithm & ACVP_SHAKE128 ||
	     xof->algorithm & ACVP_SHAKE256) &&
	    (!(xof->outlength[0] & DEF_ALG_RANGE_TYPE) ||
	     xof->outlength[1] > 65536 ||
	     acvp_range_min_val(xof->outlength) < 16)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "XOF: output min/max definition does not match requirements (16 <= n <= 65536)\n");
		return -EINVAL;
	}

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_cipher_to_string(entry, xof->algorithm,
				        ACVP_CIPHERTYPE_MAC |
				        ACVP_CIPHERTYPE_HASH, "algorithm"));
	CKINT(json_object_object_add(entry, "hexCustomization",
				     json_object_new_boolean(xof->hex)));

	CKINT(acvp_req_algo_int_array(entry, xof->messagelength, "msgLen"));

	if (xof->algorithm & ACVP_KMAC128 || xof->algorithm & ACVP_KMAC256) {
		tmp_array = json_object_new_array();
		CKNULL(tmp_array, -ENOMEM);
		if (xof->xof & DEF_ALG_XOF_NOT_PRESENT)
			CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(false)));
		if (xof->xof & DEF_ALG_XOF_PRESENT)
			CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(true)));
		CKINT(json_object_object_add(entry, "xof", tmp_array));
		tmp_array = NULL;

		CKINT(acvp_req_algo_int_array(entry, xof->keylength, "keyLen"));
		CKINT(acvp_req_algo_int_array(entry, xof->maclength, "macLen"));
	} else {
		CKINT(acvp_req_algo_int_array(entry, xof->outlength,
					      "outputLen"));
	}

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}
