/* JSON request generator for SP800-135 KDF IKE v2
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

int acvp_req_set_prereq_kdf_ikev2(const struct def_algo_kdf_ikev2 *kdf_ikev2,
				  struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("kdf-components")));
	CKINT(json_object_object_add(entry, "mode",
				     json_object_new_string("ikev2")));

	CKINT(acvp_req_gen_prereq(kdf_ikev2->prereqvals,
				  kdf_ikev2->prereqvals_num, entry, publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for KDF IKE v2
 */
int acvp_req_set_algo_kdf_ikev2(const struct def_algo_kdf_ikev2 *kdf_ikev2,
			        struct json_object *entry)
{
	struct json_object *array, *tmp;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_kdf_ikev2(kdf_ikev2, entry, false));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", array));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_array_add(array, tmp));

	CKINT(acvp_req_algo_int_array(tmp, kdf_ikev2->initiator_nonce_length,
				      "initiatorNonceLength"));

	CKINT(acvp_req_algo_int_array(tmp, kdf_ikev2->responder_nonce_length,
				      "responderNonceLength"));

	CKINT(acvp_req_algo_int_array(tmp,
				kdf_ikev2->diffie_hellman_shared_secret_length,
				"diffieHellmanSharedSecretLength"));

	CKINT(acvp_req_algo_int_array(tmp,
				      kdf_ikev2->derived_keying_material_length,
				      "derivedKeyingMaterialLength"));

	CKINT(acvp_req_cipher_to_array(tmp, kdf_ikev2->hashalg,
				       ACVP_CIPHERTYPE_HASH, "hashAlg"));

out:
	return ret;
}
