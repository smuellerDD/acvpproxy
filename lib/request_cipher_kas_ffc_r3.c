/* JSON request generator for KAS FFC rev 3 (SP800-56A rev. 3)
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
acvp_req_kas_ffc_r3_schema(const struct def_algo_kas_ffc_r3_schema *r3_schema,
			   struct json_object *entry)
{
	const struct def_algo_kas_r3_kc *kcm =
					&r3_schema->key_confirmation_method;
	struct json_object *tmp, *schema_entry;
	int ret;
	bool found = false;

	schema_entry = json_object_new_object();
	CKNULL(schema_entry, -ENOMEM);

	switch (r3_schema->schema) {
	case DEF_ALG_KAS_FFC_R3_DH_EPHEM:
		CKINT(json_object_object_add(entry, "dhEphem", schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_DH_HYBRID_1:
		CKINT(json_object_object_add(entry, "dhHybrid1", schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_MQV2:
		CKINT(json_object_object_add(entry, "mqv2", schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_DH_HYBRID_ONE_FLOW:
		CKINT(json_object_object_add(entry, "dhHybridOneFlow",
					     schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_MQV1:
		CKINT(json_object_object_add(entry, "mqv1", schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_DH_ONE_FLOW:
		CKINT(json_object_object_add(entry, "dhOneFlow", schema_entry));
		break;
	case DEF_ALG_KAS_FFC_R3_DH_STATIC:
		CKINT(json_object_object_add(entry, "dhStatic", schema_entry));
		break;
	default:
		ACVP_JSON_PUT_NULL(schema_entry);
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: No applicable entry for kas_ffc_r3_schema found\n");
		ret = -EINVAL;
		goto out;
	}

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(schema_entry, "kasRole", tmp));
	if (r3_schema->kas_ffc_role & DEF_ALG_KAS_FFC_R3_INITIATOR) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("initiator")));
		found = true;
	}
	if (r3_schema->kas_ffc_role & DEF_ALG_KAS_FFC_R3_RESPONDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("responder")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC r3: No applicable entry for kas_ffc_r3_role found\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(schema_entry, "kdfMethods", tmp));
	CKINT(acvp_req_kas_kdf_onestep_impl(&r3_schema->onestekdf, tmp));
	CKINT(acvp_req_kas_kdf_twostep_impl(r3_schema->twostekdf,
					    r3_schema->twostekdf_num,
					    r3_schema->length, tmp));

	if ((r3_schema->schema == DEF_ALG_KAS_FFC_R3_DH_EPHEM) &&
	    (kcm->kc_direction || kcm->kcrole)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: dhEphem does not require key confirmation method definition\n");
		ret = -EINVAL;
		goto out;
	}
	CKINT(acvp_req_kas_r3_kc_method(&r3_schema->key_confirmation_method,
					schema_entry));

	if ((!r3_schema->key_confirmation_method.kc_direction ||
	     !r3_schema->key_confirmation_method.kcrole) &&
	    r3_schema->length < 128) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: KAS KDF length minimum without KC is 128 bits\n");
		ret = -EINVAL;
		goto out;
	}
	if ((r3_schema->key_confirmation_method.kc_direction &&
	     r3_schema->key_confirmation_method.kcrole) &&
	    r3_schema->length < 136) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: KAS KDF length minimum with KC is 136 bits\n");
		ret = -EINVAL;
		goto out;
	}

	if (r3_schema->length > 1024) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: KAS KDF length maximum is 1024 bits\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(json_object_object_add(schema_entry, "l",
				json_object_new_int((int)r3_schema->length)));

out:
	return ret;
}

static int
_acvp_req_set_algo_kas_ffc_r3(const struct def_algo_kas_ffc_r3 *kas_ffc_r3,
			      const struct acvp_test_deps *deps,
			      struct json_object *entry, bool full,
			      bool publish)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;
	bool found = false;

	CKNULL_LOG(kas_ffc_r3->schema_num, -EINVAL,
		   "KAS FFC r3: At least one schema definition required\n");

	CKINT(acvp_req_gen_prereq(kas_ffc_r3->prereqvals,
				  kas_ffc_r3->prereqvals_num, deps,
				  entry, publish));
	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KAS-FFC")));
	CKINT(acvp_req_add_revision(entry, "Sp800-56Ar3"));

	if (!full)
		goto out;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "function", tmp));
	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_KEYPAIRGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyPairGen")));
		found = true;
	}
	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_PARTIALVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("partialVal")));
		found = true;
	}
	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_FULLVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("fullVal")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC r3: No applicable entry for kas_ffc_function found\n");

	CKNULL_LOG(kas_ffc_r3->iut_identifier, -EINVAL,
		   "KAS FFC r3: IUT identifier missing");
	CKINT(json_object_object_add(entry, "iutId",
			json_object_new_string(kas_ffc_r3->iut_identifier)));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	for (i = 0; i < kas_ffc_r3->schema_num; i++) {
		const struct def_algo_kas_ffc_r3_schema *schema =
							kas_ffc_r3->schema + i;

		CKINT(acvp_req_kas_ffc_r3_schema(schema, tmp));
	}

	CKINT_LOG(acvp_req_cipher_to_array(entry, kas_ffc_r3->domain_parameter,
					   ACVP_CIPHERTYPE_DOMAIN,
					   "domainParameterGenerationMethods"),
		  "KAS FC r3: Unknown domain parameter set\n");

out:
	return ret;
}

int acvp_list_algo_kas_ffc_r3(const struct def_algo_kas_ffc_r3 *kas_ffc_r3,
			      struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL, *prev;
	int ret;
	bool found = false;

	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_KEYPAIRGEN) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-FFC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ffc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_DOMAIN,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyPairGen"));
		found = true;
	}
	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_PARTIALVAL) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-FFC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ffc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_DOMAIN,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "partialVal"));
		found = true;
	}
	if (kas_ffc_r3->kas_ffc_function & DEF_ALG_KAS_FFC_R3_FULLVAL) {
		prev = tmp;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		*new = tmp;
		tmp->next = prev;

		CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-FFC Sp800-56Ar3"));
		CKINT(acvp_req_cipher_to_intarray(kas_ffc_r3->domain_parameter,
						  ACVP_CIPHERTYPE_DOMAIN,
						  tmp->keylen));

		CKINT(acvp_duplicate(&tmp->cipher_mode, "fullVal"));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC r3: No applicable entry for kas_ffc_function found\n");

	tmp->prereqs = kas_ffc_r3->prereqvals;
	tmp->prereq_num = kas_ffc_r3->prereqvals_num;

out:
	return ret;
}

int acvp_req_set_prereq_kas_ffc_r3(const struct def_algo_kas_ffc_r3 *kas_ffc_r3,
				   const struct acvp_test_deps *deps,
				   struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kas_ffc_r3(kas_ffc_r3, deps, entry, false,
					     publish);
}

int acvp_req_set_algo_kas_ffc_r3(const struct def_algo_kas_ffc_r3 *kas_ffc_r3,
				 struct json_object *entry)
{
	return _acvp_req_set_algo_kas_ffc_r3(kas_ffc_r3, NULL, entry, true,
					     false);
}
