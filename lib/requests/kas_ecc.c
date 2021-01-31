/* JSON request generator for KAS ECC
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

static int acvp_req_kas_ecc_paramset(enum kas_ecc_paramset kas_ecc_paramset,
				     cipher_t curve,
				     cipher_t hashalg,
				     struct json_object *entry,
				     struct json_object **paramsetptr)
{
	struct json_object *tmp, *tmp2;
	int ret = 0;

	CKNULL_LOG(curve, -EINVAL, "KAS ECC: curve value empty\n");
	CKNULL_LOG(hashalg, -EINVAL, "KAS ECC: hashalg value empty\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSet", tmp));

	tmp2 = json_object_new_object();
	CKNULL(tmp2, -ENOMEM);
	switch(kas_ecc_paramset) {
	case DEF_ALG_KAS_ECC_EB:
		CKINT(json_object_object_add(tmp, "eb", tmp2));
		break;
	case DEF_ALG_KAS_ECC_EC:
		CKINT(json_object_object_add(tmp, "ec", tmp2));
		break;
	case DEF_ALG_KAS_ECC_ED:
		CKINT(json_object_object_add(tmp, "ed", tmp2));
		break;
	case DEF_ALG_KAS_ECC_EE:
		CKINT(json_object_object_add(tmp, "ee", tmp2));
		break;
	default:
		json_object_put(tmp);
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS ECC: Unknown kas_ecc_paramset entry\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT_LOG(acvp_req_cipher_to_string(tmp2, curve, ACVP_CIPHERTYPE_ECC,
					    "curve"),
		  "KAS ECC: ECDH Cipher definition not found\n");

	CKINT(acvp_req_cipher_to_array(tmp2, hashalg, ACVP_CIPHERTYPE_HASH,
				       "hashAlg"));

	if (paramsetptr)
		*paramsetptr = tmp2;

out:
	return ret;
}

static int acvp_req_kas_ecc_mac(cipher_t mac,
				const int keylen[],
				int noncelen,
				int maclen,
				struct json_object *entry)
{
	struct json_object *tmp, *tmp2;
	const char *mac_str;
	int ret;

	CKNULL_LOG(mac, -EINVAL, "KAS ECC: mac value empty\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "macOption", tmp));

	CKINT_LOG(acvp_req_cipher_to_name(mac, ACVP_CIPHERTYPE_MAC |
					       ACVP_CIPHERTYPE_AEAD,
					  &mac_str),
		  "KAS ECC: Cannot convert mac cipher definition\n");
	tmp2 = json_object_new_object();
	CKNULL(tmp2, -ENOMEM);
	CKINT(json_object_object_add(tmp, mac_str, tmp2));

	CKINT(acvp_req_algo_int_array(tmp2, keylen, "keyLen"));

	if (maclen)
		CKINT(json_object_object_add(tmp2, "macLen",
					     json_object_new_int(maclen)));

	if ((mac & ACVP_CCM)) {
		CKNULL_LOG(noncelen, -EINVAL,
			   "KAS ECC: noncelen not provided\n");
		CKNULL_LOG(maclen, -EINVAL, "KAS ECC: maclen not provided\n");
		CKINT(json_object_object_add(tmp2, "nonceLen",
					     json_object_new_int(noncelen)));
	}

out:
	return ret;
}

static int acvp_req_kas_ecc_kdfoption(unsigned int kas_ecc_kdfoption,
				      const char *oipattern,
				      struct json_object *entry)
{
	struct json_object *tmp;
	int ret = 0;
	bool found = false;

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kdfOption", tmp));

	if (kas_ecc_kdfoption & DEF_ALG_KAS_ECC_CONCATENATION) {
		CKINT(json_object_object_add(tmp, "concatenation",
					json_object_new_string(oipattern)));
		found = true;
	}
	if (kas_ecc_kdfoption & DEF_ALG_KAS_ECC_ASN1) {
		CKINT(json_object_object_add(tmp, "ASN1",
					json_object_new_string(oipattern)));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kas_ecc_kdfoption found\n");

out:
	return ret;
}

static int
acvp_req_kas_ecc_nokdfnokc(const struct def_algo_kas_ecc_nokdfnokc *nokdfnokc,
			   struct json_object *entry)
{
	return acvp_req_kas_ecc_paramset(nokdfnokc->kas_ecc_paramset,
					 nokdfnokc->curve,
					 nokdfnokc->hashalg,
					 entry, NULL);
}

static int
acvp_req_kas_ecc_kdfnokc(const struct def_algo_kas_ecc_kdfnokc *kdfnokc,
			 struct json_object *entry)
{
	struct json_object *paramset;
	int ret;

	CKINT(acvp_req_kas_ecc_kdfoption(kdfnokc->kas_ecc_kdfoption,
					 kdfnokc->oipattern, entry));
	CKINT(acvp_req_kas_ecc_paramset(kdfnokc->kas_ecc_paramset,
					kdfnokc->curve,
					kdfnokc->hashalg,
					entry, &paramset));
	CKINT(acvp_req_kas_ecc_mac(kdfnokc->mac,
				   kdfnokc->keylen,
				   kdfnokc->noncelen,
				   kdfnokc->maclen,
				   paramset));

out:
	return ret;
}

static int acvp_req_kas_ecc_kdfkc(const struct def_algo_kas_ecc_kdfkc *kdfkc,
			   struct json_object *entry)
{
	struct json_object *paramset, *tmp;
	int ret;
	bool found = false;

	CKINT(acvp_req_kas_ecc_kdfoption(kdfkc->kas_ecc_kdfoption,
					 kdfkc->oipattern, entry));
	CKINT(acvp_req_kas_ecc_paramset(kdfkc->kas_ecc_paramset,
					kdfkc->curve,
					kdfkc->hashalg,
					entry, &paramset));

	CKINT(acvp_req_kas_ecc_mac(kdfkc->mac,
				   kdfkc->keylen,
				   kdfkc->noncelen,
				   kdfkc->maclen,
				   paramset));

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kcRole", tmp));
	if (kdfkc->kcrole & DEF_ALG_KAS_ECC_PROVIDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("provider")));
		found = true;
	}
	if (kdfkc->kcrole & DEF_ALG_KAS_ECC_RECIPIENT) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("recipient")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kcrole found\n");

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kcType", tmp));
	if (kdfkc->kctype & DEF_ALG_KAS_ECC_UNILATERAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("unilateral")));
		found = true;
	}
	if (kdfkc->kctype & DEF_ALG_KAS_ECC_BILATERAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("bilateral")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kctype found\n");

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "nonceType", tmp));
	if (kdfkc->noncetype & DEF_ALG_KAS_ECC_RANDOM_NONCE) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("randomNonce")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_ECC_TIMESTAMP) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("timestamp")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_ECC_SEQUENCE) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("sequence")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_ECC_TIMESTAMP_SEQUENCE) {
		CKINT(json_object_array_add(tmp,
				json_object_new_string("timestampSequence")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for noncetype found\n");


out:
	return ret;
}

static int acvp_req_kas_ecc_schema(const struct def_algo_kas_ecc *kas_ecc,
				   struct json_object *entry)
{
	struct json_object *tmp;
	int ret;
	bool found = false;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kasRole", tmp));
	if (kas_ecc->kas_ecc_role & DEF_ALG_KAS_ECC_INITIATOR) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("initiator")));
		found = true;
	}
	if (kas_ecc->kas_ecc_role & DEF_ALG_KAS_ECC_RESPONDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("responder")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kas_ecc_role found\n");

	switch(kas_ecc->kas_ecc_dh_type) {
	case DEF_ALG_KAS_ECC_NO_KDF_NO_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "noKdfNoKc", tmp));
		CKINT(acvp_req_kas_ecc_nokdfnokc(kas_ecc->type_info.nokdfnokc,
						 tmp));
		break;
	case DEF_ALG_KAS_ECC_KDF_NO_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "kdfNoKc", tmp));
		CKINT(acvp_req_kas_ecc_kdfnokc(kas_ecc->type_info.kdfnokc,
					       tmp));
		break;
	case DEF_ALG_KAS_ECC_KDF_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "kdfKc", tmp));
		CKINT(acvp_req_kas_ecc_kdfkc(kas_ecc->type_info.kdfkc, tmp));
		break;
	case DEF_ALG_KAS_ECC_CDH:
	default:
		json_object_put(tmp);
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS ECC: Unknown entry for kas_ecc_dh_type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}


static int acvp_list_kas_ecc_schema(const struct def_algo_kas_ecc *kas_ecc,
				    cipher_t cipher[DEF_ALG_MAX_INT])
{
	int ret;

	switch(kas_ecc->kas_ecc_dh_type) {
	case DEF_ALG_KAS_ECC_NO_KDF_NO_KC:
		CKINT(acvp_req_cipher_to_intarray(
				kas_ecc->type_info.nokdfnokc->curve,
				ACVP_CIPHERTYPE_ECC, cipher));
		break;
	case DEF_ALG_KAS_ECC_KDF_NO_KC:
		CKINT(acvp_req_cipher_to_intarray(
				kas_ecc->type_info.kdfnokc->curve,
				ACVP_CIPHERTYPE_ECC, cipher));
		break;
	case DEF_ALG_KAS_ECC_KDF_KC:
		CKINT(acvp_req_cipher_to_intarray(
				kas_ecc->type_info.kdfkc->curve,
				ACVP_CIPHERTYPE_ECC, cipher));
		break;
	case DEF_ALG_KAS_ECC_CDH:
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS ECC: Unknown entry for kas_ecc_dh_type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

/*
 * Generate algorithm entry for SHA hashes
 */
static int _acvp_req_set_algo_kas_ecc(const struct def_algo_kas_ecc *kas_ecc,
				      const struct acvp_test_deps *deps,
				      struct json_object *entry, bool full,
				      bool publish)
{
	struct json_object *tmp, *tmp2;
	int ret;
	bool found = false;

	if (full)
		CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KAS-ECC")));

	if (kas_ecc->kas_ecc_dh_type == DEF_ALG_KAS_ECC_NO_KDF_NO_KC) {
		CKINT(json_object_object_add(entry, "mode",
					json_object_new_string("Component")));
	}
	if (kas_ecc->kas_ecc_schema == DEF_ALG_KAS_ECC_CDH_COMPONENT) {
		CKINT(json_object_object_add(entry, "mode",
				json_object_new_string("CDH-Component")));
	}

	CKINT(acvp_req_gen_prereq(kas_ecc->prereqvals, kas_ecc->prereqvals_num,
				  deps, entry, publish));

	if (!full)
		goto out;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "function", tmp));
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_DPGEN) {
		CKINT(json_object_array_add(tmp,
					    json_object_new_string("dpGen")));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_DPVAL) {
		CKINT(json_object_array_add(tmp,
					    json_object_new_string("dpVal")));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_KEYPAIRGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyPairGen")));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_FULLVAL) {
		CKINT(json_object_array_add(tmp,
					    json_object_new_string("fullVal")));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_PARTIALVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("partialVal")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kas_ecc_function found\n");

	if (kas_ecc->kas_ecc_dh_type == DEF_ALG_KAS_ECC_CDH) {
		const struct def_algo_kas_ecc_cdh_component *cdh_component =
					kas_ecc->type_info.cdh_component;

		if (kas_ecc->kas_ecc_schema != DEF_ALG_KAS_ECC_CDH_COMPONENT) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS ECC: kas_ecc_dh_type points to CDH component but kas_ecc_schema does not\n");
			ret = -EINVAL;
			goto out;
		}

		ret = acvp_req_cipher_to_array(entry, cdh_component->curves,
					       ACVP_CIPHERTYPE_ECC, "curve");
		/* we are done */
		goto out;
	}

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	found = false;
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_EPHEMERAL_UNIFIED) {
		if (kas_ecc->kas_ecc_dh_type == DEF_ALG_KAS_ECC_KDF_KC) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "KAS ECC: ephemeralUnified does not support key confirmation\n");
			ret = -EINVAL;
			goto out;
		}

		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "ephemeralUnified", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_FULL_MQV) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "fullMqv", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_FULL_UNIFIED) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "fullUnified", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_ONE_PASS_DH) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "onePassDh", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_ONE_PASS_MQV) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "onePassMqv", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_ONE_PASS_UNIFIED) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		json_object_object_add(tmp, "onePassUnified", tmp2);
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	if (kas_ecc->kas_ecc_schema & DEF_ALG_KAS_ECC_STATIC_UNIFIED) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "staticUnified", tmp2));
		CKINT(acvp_req_kas_ecc_schema(kas_ecc, tmp2));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kas_ecc_schema found\n");

out:
	return ret;
}

int acvp_list_algo_kas_ecc(const struct def_algo_kas_ecc *kas_ecc,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;
	bool found = false;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-ECC"));
	tmp->prereqs = kas_ecc->prereqvals;
	tmp->prereq_num = kas_ecc->prereqvals_num;

	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_DPGEN) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "dpGen"));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_DPVAL) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "dpVal"));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_KEYPAIRGEN) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyPairGen"));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_FULLVAL) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "fullVal"));
		found = true;
	}
	if (kas_ecc->kas_ecc_function & DEF_ALG_KAS_ECC_PARTIALVAL) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "partialVal"));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS ECC: No applicable entry for kas_ecc_function found\n");

	if (kas_ecc->kas_ecc_dh_type == DEF_ALG_KAS_ECC_CDH) {
		const struct def_algo_kas_ecc_cdh_component *cdh_component =
					kas_ecc->type_info.cdh_component;

		CKINT(acvp_req_cipher_to_intarray(cdh_component->curves,
						  ACVP_CIPHERTYPE_ECC,
						  tmp->keylen));
		/* we are done */
		goto out;
	}

	CKINT(acvp_list_kas_ecc_schema(kas_ecc, tmp->keylen));

out:
	return ret;
}

int acvp_req_set_prereq_kas_ecc(const struct def_algo_kas_ecc *kas_ecc,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kas_ecc(kas_ecc, deps, entry, false, publish);
}

int acvp_req_set_algo_kas_ecc(const struct def_algo_kas_ecc *kas_ecc,
			      struct json_object *entry)
{
	return _acvp_req_set_algo_kas_ecc(kas_ecc, NULL, entry, true, false);
}
