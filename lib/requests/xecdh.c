/* JSON generator for XECDH ciphers
 *
 * Copyright (C) 2026, Joachim Vandersmissen <joachim.vandersmissen@atsec.com>
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
 * Generate algorithm entry for XECDH
 */
static int _acvp_req_set_algo_xecdh(const struct def_algo_xecdh *xecdh,
				    const struct acvp_test_deps *deps,
				    struct json_object *entry, bool full,
				    bool publish)
{
	int ret = -EINVAL;

	switch (xecdh->xecdh_mode) {
	case DEF_ALG_XECDH_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("XECDH")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		break;
	case DEF_ALG_XECDH_MODE_KEYVER:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("XECDH")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyVer")));
		break;
	case DEF_ALG_XECDH_MODE_SSC:
		CKINT(json_object_object_add(entry, "algorithm",
					     json_object_new_string("XECDH")));
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("SSC")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "XECDH: Unknown XECDH definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if (full) {
		CKINT(acvp_req_add_revision(entry, "RFC7748"));
		CKINT(acvp_req_cipher_to_array(entry, xecdh->curve,
					       ACVP_CIPHERTYPE_ECC, "curve"));
	}

	CKINT(acvp_req_gen_prereq(xecdh->prereqvals, xecdh->prereqvals_num,
				  deps, entry, publish));

	ret = 0;

out:
	return ret;
}

int acvp_list_algo_xecdh(const struct def_algo_xecdh *xecdh,
			 struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_req_cipher_to_intarray(xecdh->curve, ACVP_CIPHERTYPE_ECC,
					  tmp->keylen));
	tmp->prereqs = xecdh->prereqvals;
	tmp->prereq_num = xecdh->prereqvals_num;

	switch (xecdh->xecdh_mode) {
	case DEF_ALG_XECDH_MODE_KEYGEN:
		CKINT(acvp_duplicate(&tmp->cipher_name, "XECDH"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		break;
	case DEF_ALG_XECDH_MODE_KEYVER:
		CKINT(acvp_duplicate(&tmp->cipher_name, "XECDH"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyVer"));
		break;
	case DEF_ALG_XECDH_MODE_SSC:
		CKINT(acvp_duplicate(&tmp->cipher_name, "XECDH"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "SSC"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "XECDH: Unknown XECDH mode\n");
		ret = -EINVAL;
		goto out;
		break;
	}

out:
	return ret;
}

int acvp_req_set_prereq_xecdh(const struct def_algo_xecdh *xecdh,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_xecdh(xecdh, deps, entry, false, publish);
}

int acvp_req_set_algo_xecdh(const struct def_algo_xecdh *xecdh,
			    struct json_object *entry)
{
	return _acvp_req_set_algo_xecdh(xecdh, NULL, entry, true, false);
}
