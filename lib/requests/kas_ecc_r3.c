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
acvp_req_kas_ecc_r3_schema(const struct def_algo_kas_ecc_r3_schema *r3_schema,
			   struct json_object *entry, bool ssc)
{
	const struct def_algo_kas_r3_kc *kcm =
					&r3_schema->key_confirmation_method;
	struct json_object *tmp, *schema_entry;
	int ret;
	bool found = false;

	schema_entry = json_object_new_object();
	CKNULL(schema_entry, -ENOMEM);

	switch (r3_schema->schema) {
	case DEF_ALG_KAS_ECC_R3_EPHEMERAL_UNIFIED:
		CKINT(json_object_object_add(entry, "ephemeralUnified",
					     schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_FULL_MQV:
		CKINT(json_object_object_add(entry, "fullMqv", schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_FULL_UNIFIED:
		CKINT(json_object_object_add(entry, "fullUnified",
					     schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_ONE_PASS_DH:
		CKINT(json_object_object_add(entry, "onePassDh",
					     schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_ONE_PASS_MQV:
		CKINT(json_object_object_add(entry, "onePassMqv",
					     schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_ONE_PASS_UNIFIED:
		CKINT(json_object_object_add(entry, "onePassUnified",
					     schema_entry));
		break;
	case DEF_ALG_KAS_ECC_R3_STATIC_UNIFIED:
		CKINT(json_object_object_add(entry, "staticUnified", schema_entry));
		break;
	default:
		ACVP_JSON_PUT_NULL(schema_entry);
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: No applicable entry for kas_ecc_r3_schema found\n");
		ret = -EINVAL;
		goto out;
	}

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(schema_entry, "kasRole", tmp));
	if (r3_schema->kas_ecc_role & DEF_ALG_KAS_ECC_R3_INITIATOR) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("initiator")));
		found = true;
	}
	if (r3_schema->kas_ecc_role & DEF_ALG_KAS_ECC_R3_RESPONDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("responder")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC r3: No applicable entry for kas_ecc_r3_role found\n");

	if (ssc)
		goto out;

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(schema_entry, "kdfMethods", tmp));
	CKINT(acvp_req_kas_kdf_onestep_impl(&r3_schema->onestepkdf, tmp));
	CKINT(acvp_req_kas_kdf_twostep_impl(r3_schema->twostepkdf,
					    r3_schema->twostepkdf_num,
					    r3_schema->length, tmp));

	if ((r3_schema->schema == DEF_ALG_KAS_ECC_R3_EPHEMERAL_UNIFIED) &&
	    (kcm->kc_direction || kcm->kcrole)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: ephemeralUnified does not require key confirmation method definition\n");
		ret = -EINVAL;
		goto out;
	}
	CKINT(acvp_req_kas_r3_kc_method(kcm, schema_entry));

	if ((!r3_schema->key_confirmation_method.kc_direction ||
	     !r3_schema->key_confirmation_method.kcrole) &&
	    r3_schema->length < 128) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: KAS KDF length minimum without KC is 128 bits\n");
		ret = -EINVAL;
		goto out;
	}
	if ((r3_schema->key_confirmation_method.kc_direction &&
	     r3_schema->key_confirmation_method.kcrole) &&
	    r3_schema->length < 136) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: KAS KDF length minimum with KC is 136 bits\n");
		ret = -EINVAL;
		goto out;
	}

	if (r3_schema->length > 1024) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS ECC r3: KAS KDF length maximum is 1024 bits\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(json_object_object_add(schema_entry, "l",
				json_object_new_int((int)r3_schema->length)));

out:
	return ret;
}

static int
acvp_req_set_algo_kas_ecc_ssc_r3(const struct def_algo_kas_ecc_r3 *kas_ecc_r3,
				 struct json_object *entry, bool full)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KAS-ECC-SSC")));
	if (!full)
		goto out;

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	for (i = 0; i < kas_ecc_r3->schema_num; i++) {
		const struct def_algo_kas_ecc_r3_schema *schema =
							kas_ecc_r3->schema + i;

		CKINT(acvp_req_kas_ecc_r3_schema(schema, tmp, true));
	}

	CKINT_LOG(acvp_req_cipher_to_array(entry, kas_ecc_r3->domain_parameter,
					   ACVP_CIPHERTYPE_ECC,
					   "domainParameterGenerationMethods"),
		  "KAS ECC r3: Unknown domain parameter set\n");

	if (kas_ecc_r3->hash_z) {
		CKINT_LOG(acvp_req_cipher_to_string(entry, kas_ecc_r3->hash_z,
						    ACVP_CIPHERTYPE_HASH,
						    "hashFunctionZ"),
			  "KAS ECC r3 SSC: Unknown hash\n");
	}

out:
	return ret;
}

static int
_acvp_req_set_algo_kas_ecc_r3(const struct def_algo_kas_ecc_r3 *kas_ecc_r3,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool full,
			      bool publish)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;
	bool found = false;

	CKNULL_LOG(kas_ecc_r3->schema_num, -EINVAL,
		   "KAS ECC r3: At least one schema definition required\n");

	CKINT(acvp_req_gen_prereq(kas_ecc_r3->prereqvals,
				  kas_ecc_r3->prereqvals_num, deps, entry,
				  publish));
	CKINT(acvp_req_add_revision(entry, "Sp800-56Ar3"));

	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_SSC) {
		if ((kas_ecc_r3->kas_ecc_function &
		     (unsigned int)~DEF_ALG_KAS_ECC_R3_SSC) != 0) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS ECC SSC can only be defined by itself and not with other KAS ECC function types.\n");
		}
		return acvp_req_set_algo_kas_ecc_ssc_r3(kas_ecc_r3, entry,
							full);
	}

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KAS-ECC")));

	if (!full)
		goto out;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "function", tmp));
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_KEYPAIRGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyPairGen")));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_PARTIALVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("partialVal")));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_FULLVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("fullVal")));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_SSC) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("fullVal")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC r3: No applicable entry for kas_ecc_function found\n");

	CKNULL_LOG(kas_ecc_r3->iut_identifier, -EINVAL,
		   "KAS ECC r3: IUT identifier missing");
	CKINT(json_object_object_add(entry, "iutId",
			json_object_new_string(kas_ecc_r3->iut_identifier)));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	for (i = 0; i < kas_ecc_r3->schema_num; i++) {
		const struct def_algo_kas_ecc_r3_schema *schema =
							kas_ecc_r3->schema + i;

		CKINT(acvp_req_kas_ecc_r3_schema(schema, tmp, false));
	}

	CKINT_LOG(acvp_req_cipher_to_array(entry, kas_ecc_r3->domain_parameter,
					   ACVP_CIPHERTYPE_ECC,
					   "domainParameterGenerationMethods"),
		  "KAS ECC r3: Unknown domain parameter set\n");

out:
	return ret;
}

int acvp_list_algo_kas_ecc_r3(const struct def_algo_kas_ecc_r3 *kas_ecc_r3,
			      struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL, *prev;
	int ret = 0;
	bool found = false;

	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_KEYPAIRGEN) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-ECC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ecc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_ECC,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyPairGen"));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_PARTIALVAL) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-ECC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ecc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_ECC,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "partialVal"));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_FULLVAL) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-ECC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ecc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_ECC,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "fullVal"));
		found = true;
	}
	if (kas_ecc_r3->kas_ecc_function & DEF_ALG_KAS_ECC_R3_SSC) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name,
				     "KAS-ECC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ecc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_ECC,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "SSC"));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC r3: No applicable entry for kas_ecc_function found\n");

	tmp->prereqs = kas_ecc_r3->prereqvals;
	tmp->prereq_num = kas_ecc_r3->prereqvals_num;


out:
	return ret;
}

int acvp_req_set_prereq_kas_ecc_r3(const struct def_algo_kas_ecc_r3 *kas_ecc_r3,
				   const struct acvp_test_deps *deps,
				   struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kas_ecc_r3(kas_ecc_r3, deps, entry, false,
					     publish);
}

int acvp_req_set_algo_kas_ecc_r3(const struct def_algo_kas_ecc_r3 *kas_ecc_r3,
				 struct json_object *entry)
{
	return _acvp_req_set_algo_kas_ecc_r3(kas_ecc_r3, NULL, entry, true,
					     false);
}
