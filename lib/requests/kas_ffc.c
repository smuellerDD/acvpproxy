/* JSON request generator for KAS FFC
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "term_colors.h"

static int acvp_req_kas_ffc_paramset(enum kas_ffc_paramset kas_ffc_paramset,
				     cipher_t hashalg,
				     struct json_object *entry,
				     struct json_object **paramsetptr)
{
	struct json_object *tmp, *tmp2;
	int ret = 0;

	CKNULL_LOG(hashalg, -EINVAL, "KAS FFC: hashalg value empty\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "parameterSet", tmp));

	tmp2 = json_object_new_object();
	CKNULL(tmp2, -ENOMEM);
	switch(kas_ffc_paramset) {
	case DEF_ALG_KAS_FFC_FB:
		CKINT(json_object_object_add(tmp, "fb", tmp2));
		break;
	case DEF_ALG_KAS_FFC_FC:
		CKINT(json_object_object_add(tmp, "fc", tmp2));
		break;
	default:
		json_object_put(tmp);
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS FFC: Unknown kas_ffc_paramset entry\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(acvp_req_cipher_to_array(tmp2, hashalg, ACVP_CIPHERTYPE_HASH,
				       "hashAlg"));

	if (paramsetptr)
		*paramsetptr = tmp2;

out:
	return ret;
}

static int acvp_list_kas_ffc_paramset(enum kas_ffc_paramset kas_ffc_paramset,
				      char **str)
{
	char buf[15];
	int ret = 0;

	memset(buf, 0, sizeof(buf));

	switch(kas_ffc_paramset) {
	case DEF_ALG_KAS_FFC_FB:
		CKINT(acvp_extend_string(buf, sizeof(buf), "2048/224"));
		break;
	case DEF_ALG_KAS_FFC_FC:
		CKINT(acvp_extend_string(buf, sizeof(buf), "2048/256"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS FFC: Unknown kas_ffc_paramset entry\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(acvp_duplicate(str, buf));

out:
	return ret;
}

static int acvp_req_kas_ffc_mac(cipher_t mac,
				const int keylen[],
				int noncelen,
				int maclen,
				struct json_object *entry)
{
	struct json_object *tmp, *tmp2;
	const char *mac_str;
	int ret;

	CKNULL_LOG(mac, -EINVAL, "KAS FFC: mac value empty\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "macOption", tmp));

	CKINT_LOG(acvp_req_cipher_to_name(mac, ACVP_CIPHERTYPE_MAC |
					       ACVP_CIPHERTYPE_AEAD,
					  &mac_str),
		  "KAS FFC: Cannot convert mac cipher definition\n");
	tmp2 = json_object_new_object();
	CKNULL(tmp2, -ENOMEM);
	CKINT(json_object_object_add(tmp, mac_str, tmp2));

	CKINT(acvp_req_algo_int_array(tmp2, keylen, "keyLen"));

	if ((mac & ACVP_CCM) == ACVP_CCM) {
		CKNULL_LOG(noncelen, -EINVAL,
			   "KAS FFC: noncelen not provided\n");
		CKNULL_LOG(maclen, -EINVAL, "KAS FFC: maclen not provided\n");
		CKINT(json_object_object_add(tmp2, "nonceLen",
					     json_object_new_int(noncelen)));
		CKINT(json_object_object_add(tmp2, "macLen",
					     json_object_new_int(maclen)));
	}

out:
	return ret;
}

static int acvp_req_kas_ffc_kdfoption(unsigned int kas_ffc_kdfoption,
				      const char *oipattern,
				      struct json_object *entry)
{
	struct json_object *tmp;
	int ret = 0;
	bool found = false;

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kdfOption", tmp));

	if (kas_ffc_kdfoption & DEF_ALG_KAS_FFC_CONCATENATION) {
		CKINT(json_object_object_add(tmp, "concatenation",
					json_object_new_string(oipattern)));
		found = true;
	}
	if (kas_ffc_kdfoption & DEF_ALG_KAS_FFC_ASN1) {
		CKINT(json_object_object_add(tmp, "ASN1",
					json_object_new_string(oipattern)));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for kas_ffc_kdfoption found\n");

out:
	return ret;
}

static int
acvp_req_kas_ffc_nokdfnokc(const struct def_algo_kas_ffc_nokdfnokc *nokdfnokc,
			   struct json_object *entry)
{
	return acvp_req_kas_ffc_paramset(nokdfnokc->kas_ffc_paramset,
					 nokdfnokc->hashalg,
					 entry, NULL);
}

static int
acvp_req_kas_ffc_kdfnokc(const struct def_algo_kas_ffc_kdfnokc *kdfnokc,
			 struct json_object *entry)
{
	struct json_object *paramset;
	int ret;

	CKINT(acvp_req_kas_ffc_kdfoption(kdfnokc->kas_ffc_kdfoption,
					 kdfnokc->oipattern, entry));
	CKINT(acvp_req_kas_ffc_paramset(kdfnokc->kas_ffc_paramset,
					kdfnokc->hashalg,
					entry, &paramset));
	CKINT(acvp_req_kas_ffc_mac(kdfnokc->mac,
				   kdfnokc->keylen,
				   kdfnokc->noncelen,
				   kdfnokc->maclen,
				   paramset));

out:
	return ret;
}

static int acvp_req_kas_ffc_kdfkc(const struct def_algo_kas_ffc_kdfkc *kdfkc,
			   struct json_object *entry)
{
	struct json_object *paramset, *tmp;
	int ret;
	bool found = false;

	CKINT(acvp_req_kas_ffc_kdfoption(kdfkc->kas_ffc_kdfoption,
					 kdfkc->oipattern, entry));
	CKINT(acvp_req_kas_ffc_paramset(kdfkc->kas_ffc_paramset,
					kdfkc->hashalg,
					entry, &paramset));

	CKINT(acvp_req_kas_ffc_mac(kdfkc->mac,
				   kdfkc->keylen,
				   kdfkc->noncelen,
				   kdfkc->maclen,
				   paramset));

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kcRole", tmp));
	if (kdfkc->kcrole & DEF_ALG_KAS_FFC_PROVIDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("provider")));
		found = true;
	}
	if (kdfkc->kcrole & DEF_ALG_KAS_FFC_RECIPIENT) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("recipient")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for kcrole found\n");

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kcType", tmp));
	if (kdfkc->kctype & DEF_ALG_KAS_FFC_UNILATERAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("unilateral")));
		found = true;
	}
	if (kdfkc->kctype & DEF_ALG_KAS_FFC_BILATERAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("bilateral")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for kctype found\n");

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "nonceType", tmp));
	if (kdfkc->noncetype & DEF_ALG_KAS_FFC_RANDOM_NONCE) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("randomNonce")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_FFC_TIMESTAMP) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("timestamp")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_FFC_SEQUENCE) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("sequence")));
		found = true;
	}
	if (kdfkc->noncetype & DEF_ALG_KAS_FFC_TIMESTAMP_SEQUENCE) {
		CKINT(json_object_array_add(tmp,
				json_object_new_string("timestampSequence")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for noncetype found\n");


out:
	return ret;
}

static int acvp_req_kas_ffc_schema(const struct def_algo_kas_ffc *kas_ffc,
				   struct json_object *entry)
{
	struct json_object *tmp;
	int ret;
	bool found = false;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "kasRole", tmp));
	if (kas_ffc->kas_ffc_role & DEF_ALG_KAS_FFC_INITIATOR) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("initiator")));
		found = true;
	}
	if (kas_ffc->kas_ffc_role & DEF_ALG_KAS_FFC_RESPONDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("responder")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for kas_ffc_role found\n");

	switch(kas_ffc->kas_ffc_dh_type) {
	case DEF_ALG_KAS_FFC_NO_KDF_NO_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "noKdfNoKc", tmp));
		CKINT(acvp_req_kas_ffc_nokdfnokc(kas_ffc->type_info.nokdfnokc,
						 tmp));
		break;
	case DEF_ALG_KAS_FFC_KDF_NO_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "kdfNoKc", tmp));
		CKINT(acvp_req_kas_ffc_kdfnokc(kas_ffc->type_info.kdfnokc,
					       tmp));
		break;
	case DEF_ALG_KAS_FFC_KDF_KC:
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "kdfKc", tmp));
		CKINT(acvp_req_kas_ffc_kdfkc(kas_ffc->type_info.kdfkc, tmp));
		break;
	default:
		json_object_put(tmp);
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS FFC: Unknown entry for kas_ffc_dh_type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

static int acvp_list_kas_ffc_schema(const struct def_algo_kas_ffc *kas_ffc,
				    char **str)
{
	int ret;

	switch(kas_ffc->kas_ffc_dh_type) {
	case DEF_ALG_KAS_FFC_NO_KDF_NO_KC:
		CKINT(acvp_list_kas_ffc_paramset(
			kas_ffc->type_info.nokdfnokc->kas_ffc_paramset, str));
		break;
	case DEF_ALG_KAS_FFC_KDF_NO_KC:
		CKINT(acvp_list_kas_ffc_paramset(
			kas_ffc->type_info.kdfnokc->kas_ffc_paramset, str));
		break;
	case DEF_ALG_KAS_FFC_KDF_KC:
		CKINT(acvp_list_kas_ffc_paramset(
			kas_ffc->type_info.kdfkc->kas_ffc_paramset, str));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "KAS FFC: Unknown entry for kas_ffc_dh_type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

/*
 * Generate algorithm entry for SHA hashes
 */
static int _acvp_req_set_algo_kas_ffc(const struct def_algo_kas_ffc *kas_ffc,
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
				     json_object_new_string("KAS-FFC")));

	if (kas_ffc->kas_ffc_dh_type == DEF_ALG_KAS_FFC_NO_KDF_NO_KC) {
		CKINT(json_object_object_add(entry, "mode",
					json_object_new_string("Component")));
	}

	CKINT(acvp_req_gen_prereq(kas_ffc->prereqvals, kas_ffc->prereqvals_num,
				  deps, entry, publish));

	if (!full)
		goto out;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "function", tmp));
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_DPGEN) {
		CKINT(json_object_array_add(tmp,
					    json_object_new_string("dpGen")));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_DPVAL) {
		CKINT(json_object_array_add(tmp,
					    json_object_new_string("dpVal")));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_KEYPAIRGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyPairGen")));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_FULLVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("fullVal")));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_KEYREGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyRegen")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "No applicable entry for kas_ffc_function found\n");

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	found = false;
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_DH_EPHEM) {
		if (kas_ffc->kas_ffc_dh_type == DEF_ALG_KAS_FFC_KDF_KC) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "KAS FFC: ephemeralUnified does not support key confirmation\n");
			ret = -EINVAL;
			goto out;
		}

		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "dhEphem", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_DH_HYBRID_1) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "dhHybrid1", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_MQV2) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "MQV2", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_DH_HYBRID_ONE_FLOW) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "dhHybridOneFlow", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_MQV1) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "MQV1", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_DH_ONE_FLOW) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "dhOneFlow", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	if (kas_ffc->kas_ffc_schema & DEF_ALG_KAS_FFC_DH_STATIC) {
		tmp2 = json_object_new_object();
		CKNULL(tmp2, -ENOMEM);
		CKINT(json_object_object_add(tmp, "dhStatic", tmp2));
		CKINT(acvp_req_kas_ffc_schema(kas_ffc, tmp2));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC: No applicable entry for kas_ffc_schema found\n");

out:
	return ret;
}

int acvp_list_algo_kas_ffc(const struct def_algo_kas_ffc *kas_ffc,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret = 0;
	bool found = false;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_duplicate(&tmp->cipher_name, "KAS-FFC"));
	tmp->prereqs = kas_ffc->prereqvals;
	tmp->prereq_num = kas_ffc->prereqvals_num;

	/*
	 * TODO --list-cipher-options will fail when more than one option is
	 * defined here as we allocate the same buffer multiple times. A kind of
	 * realloc would be needed here to extend the string once allocated.
	 *
	 * We leave it unfixed for now as this algo is sunset anyways.
	 */
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_DPGEN) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "dpGen"));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_DPVAL) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "dpVal"));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_KEYPAIRGEN) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyPairGen"));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_FULLVAL) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "fullVal"));
		found = true;
	}
	if (kas_ffc->kas_ffc_function & DEF_ALG_KAS_FFC_KEYREGEN) {
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyRegen"));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "No applicable entry for kas_ffc_function found\n");

	CKINT(acvp_list_kas_ffc_schema(kas_ffc, &tmp->cipher_aux));

out:
	return ret;
}

int acvp_req_set_prereq_kas_ffc(const struct def_algo_kas_ffc *kas_ffc,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kas_ffc(kas_ffc, deps, entry, false, publish);
}

int acvp_req_set_algo_kas_ffc(const struct def_algo_kas_ffc *kas_ffc,
			      struct json_object *entry)
{
	fprintf_red(stderr,
		    "SP800-56A rev 1 KAS_FFC algorithm selected - please remove it from your definition\n");
	return _acvp_req_set_algo_kas_ffc(kas_ffc, NULL, entry, true, false);
}
