/* JSON request generator for RFC8446 KDF TLS 1.3
 *
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

int acvp_req_set_prereq_kdf_tls13(const struct def_algo_kdf_tls13 *kdf_tls13,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("TLS-v1.3")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("KDF")));

	CKINT(acvp_req_gen_prereq(kdf_tls13->prereqvals,
				  kdf_tls13->prereqvals_num,
				  deps, entry, publish));

out:
	return ret;
}

int acvp_list_algo_kdf_tls13(const struct def_algo_kdf_tls13 *kdf_tls13,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret;

	(void)kdf_tls13;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "TLS-v1.3"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "KDF"));
	CKINT(acvp_req_cipher_to_stringarray(kdf_tls13->hashalg,
					     ACVP_CIPHERTYPE_HASH,
					     &tmp->cipher_aux));
	tmp->prereqs = kdf_tls13->prereqvals;
	tmp->prereq_num = kdf_tls13->prereqvals_num;
	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

/*
 * Generate algorithm entry for KDF TLS
 */
int acvp_req_set_algo_kdf_tls13(const struct def_algo_kdf_tls13 *kdf_tls13,
			        struct json_object *entry)
{
	struct json_object *run;
	int ret;
	bool found = false;

	CKINT(acvp_req_add_revision(entry, "RFC8446"));

	CKINT(acvp_req_set_prereq_kdf_tls13(kdf_tls13, NULL, entry, false));

	CKINT(acvp_req_cipher_to_array(entry, kdf_tls13->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hmacAlg"));

	run = json_object_new_array();
	CKNULL(run, -ENOMEM);
	CKINT(json_object_object_add(entry, "runningMode", run));

	if (kdf_tls13->running_mode & DEF_ALG_KDF_TLS13_MODE_DHE) {
		CKINT(json_object_array_add(run,
					    json_object_new_string("DHE")));
		found = true;
	}
	if (kdf_tls13->running_mode &  DEF_ALG_KDF_TLS13_MODE_PSK) {
		CKINT(json_object_array_add(run,
					    json_object_new_string("PSK")));
		found = true;
	}
	if (kdf_tls13->running_mode & DEF_ALG_KDF_TLS13_MODE_PSK_DHE) {
		CKINT(json_object_array_add(run,
					    json_object_new_string("PSK-DHE")));
		found = true;
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "TLS v1.3: Unknown running mode definition\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}
