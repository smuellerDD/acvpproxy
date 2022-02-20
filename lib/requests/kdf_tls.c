/* JSON request generator for SP800-135 KDF TLS
 *
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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

int acvp_req_set_prereq_kdf_tls(const struct def_algo_kdf_tls *kdf_tls,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("tls")));

	CKINT(acvp_req_gen_prereq(kdf_tls->prereqvals, kdf_tls->prereqvals_num,
				  deps, entry, publish));

out:
	return ret;
}

int acvp_list_algo_kdf_tls(const struct def_algo_kdf_tls *kdf_tls,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret;

	(void)kdf_tls;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "kdf-components"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "tls"));
	CKINT(acvp_req_cipher_to_stringarray(kdf_tls->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = kdf_tls->prereqvals;
	tmp->prereq_num = kdf_tls->prereqvals_num;
	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

/*
 * Generate algorithm entry for KDF TLS
 */
int acvp_req_set_algo_kdf_tls(const struct def_algo_kdf_tls *kdf_tls,
			      struct json_object *entry)
{
	struct json_object *version;
	int ret;
	bool found = false;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_kdf_tls(kdf_tls, NULL, entry, false));

	version = json_object_new_array();
	CKNULL(version, -ENOMEM);
	CKINT(json_object_object_add(entry, "tlsVersion", version));
	if (kdf_tls->tls_version & DEF_ALG_KDF_TLS_1_0_1_1) {
		CKINT(json_object_array_add(version,
					json_object_new_string("v1.0/1.1")));
		found = true;
	}
	if (kdf_tls->tls_version & DEF_ALG_KDF_TLS_1_2) {
		CKINT(json_object_array_add(version,
					    json_object_new_string("v1.2")));

		if (!(kdf_tls->hashalg & ACVP_SHA256 ||
		      kdf_tls->hashalg & ACVP_SHA384 ||
	              kdf_tls->hashalg & ACVP_SHA512)) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "KDF TLS: only ACVP_SHA256, ACVP_SHA384 and ACVP_SHA512 allowed for cipher definition\n");
		}
		found = true;

		CKINT(acvp_req_cipher_to_array(entry, kdf_tls->hashalg,
					       ACVP_CIPHERTYPE_HASH, "hashAlg"));
	}
	CKNULL_LOG(found, -EINVAL, "kdf_tls contains wrong value\n");

out:
	return ret;
}
