/* JSON request generator for KAS ECC rev 3 (SP800-56A rev. 3)
 *
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

static int
_acvp_req_set_algo_kdf_onestep(const struct def_algo_kdf_onestep *kdf_onestep,
			       const struct acvp_test_deps *deps,
			       struct json_object *entry, bool full,
			       bool publish)
{
	int ret;

	CKINT(acvp_req_gen_prereq(kdf_onestep->prereqvals,
				  kdf_onestep->prereqvals_num, deps, entry,
				  publish));

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KAS-KDF")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("OneStep")));
	CKINT(acvp_req_add_revision(entry, "Sp800-56Cr1"));

	if (!full)
		goto out;

	if (kdf_onestep->length > 2048) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: KAS KDF length maximum is 1024 bits\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(json_object_object_add(entry, "l",
				json_object_new_int((int)kdf_onestep->length)));

	CKINT(acvp_req_algo_int_array(entry, kdf_onestep->zlen, "z"));

	CKINT(acvp_req_kas_kdf_onestep_def(&kdf_onestep->onestep,
					   entry));

out:
	return ret;
}

int acvp_list_algo_kdf_onestep(const struct def_algo_kdf_onestep *kdf_onestep,
			       struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-KDF Sp800-56Cr1"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "OneStep"));

	tmp->prereqs = kdf_onestep->prereqvals;
	tmp->prereq_num = kdf_onestep->prereqvals_num;

out:
	return ret;
}

int
acvp_req_set_prereq_kdf_onestep(const struct def_algo_kdf_onestep *kdf_onestep,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kdf_onestep(kdf_onestep, deps, entry, false,
					      publish);
}

int
acvp_req_set_algo_kdf_onestep(const struct def_algo_kdf_onestep *kdf_onestep,
			      struct json_object *entry)
{
	return _acvp_req_set_algo_kdf_onestep(kdf_onestep, NULL, entry, true,
					      false);
}
