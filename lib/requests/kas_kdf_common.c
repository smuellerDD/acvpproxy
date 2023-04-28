/* JSON request generator for KAS KDF (onestep, twostep) and MAC methods
 *
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>

#include "definition.h"
#include "logger.h"
#include "internal.h"
#include "request_helper.h"

int
acvp_req_kas_kdf_fi(const enum kas_kdf_fixedinfo_pattern
		    fixed_info_pattern_type[DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN],
		    const char *literal,
		    enum kas_kdf_fixedinfo_encoding fixed_info_encoding,
		    const char *key, struct json_object *entry)
{
	struct json_object *array;
	char buf[1024];
	unsigned int i;
	int ret;
	bool first_in = false;

	buf[0] = '\0';

	if (!fixed_info_pattern_type[0]) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FixedInfo: Fixed Info definition missing\n");
		return -EINVAL;
	}

	//TODO merge issue 800
	for (i = 0;
	     i < DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN &&
	      fixed_info_pattern_type[i] != 0;
	     i++) {
		switch (fixed_info_pattern_type[i]) {
		case DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL:
			CKNULL_LOG(literal, -EINVAL,
				   "KAS FixedInfo: literal string missing\n");
			if (strlen(literal) % 2) {
				logger(LOGGER_ERR, LOGGER_C_ANY,
				       "Literal hex string must be an even number of characters\n");
				ret = -EINVAL;
				goto out;
			}
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s[%s]",
						 first_in ? "||" : "",
						 "literal", literal));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "uPartyInfo"));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "vPartyInfo"));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "context"));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "algorithmId"));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_LABEL:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "label"));
			break;
		case DEF_ALG_KAS_KDF_FI_PATTERN_DKMLENGTH:
			CKINT(acvp_extend_string(buf, sizeof(buf), "%s%s",
						 first_in ? "||" : "",
						 "l"));
			break;
		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS FixedInfo: Unknown Fixed Info Pattern\n");
			return -EINVAL;
		}

		first_in = true;
	}

	CKINT(json_object_object_add(entry, key, json_object_new_string(buf)));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "encoding", array));
	switch (fixed_info_encoding) {
	case DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION:
		CKINT(json_object_array_add(array,
				json_object_new_string("concatenation")));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FixedInfo: Unknown Fixed Info encoding type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

int
acvp_req_kas_mac_salt(unsigned int mac_salt_method,  int saltlen,
		      struct json_object *entry)
{
	struct json_object *mode;
	int ret;
	bool found = false;

	mode = json_object_new_array();
	CKNULL(mode, -ENOMEM);
	CKINT(json_object_object_add(entry, "macSaltMethods", mode));

	if (mac_salt_method & DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT) {
		CKINT(json_object_array_add(mode,
				json_object_new_string("default")));
		found = true;
	}
	if (mac_salt_method & DEF_ALG_KAS_KDF_MAC_SALT_RANDOM) {
		CKINT(json_object_array_add(mode,
				json_object_new_string("random")));
		found = true;
	}

	if (saltlen) {
		CKINT(json_object_object_add(entry, "saltLen",
					     json_object_new_int(saltlen)));
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
			"KAS MAC: MAC salt method not set\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}

int
acvp_req_kas_kdf_twostep_def(const struct def_algo_kas_kdf_twostepkdf *twostep,
			     unsigned int twostekdf_num,
			     unsigned int supported_length,
			     struct json_object *ts)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;

	/* aux functions */
	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(ts, "capabilities", tmp));

	for (i = 0; i < twostekdf_num; i++) {
		struct json_object *cap;
		const struct def_algo_kas_kdf_twostepkdf *two = twostep + i;
		const struct def_algo_kdf_108 *kdf_108 = &two->kdf_108;

		cap = json_object_new_object();
		CKNULL(ts, -ENOMEM);
		CKINT(json_object_array_add(tmp, cap));

		CKINT(acvp_req_kas_mac_salt(two->mac_salt_method, two->saltlen,
					    cap));

		CKINT(acvp_req_kas_kdf_fi(two->fixed_info_pattern_type,
					  two->literal,
					  two->fixed_info_encoding,
					  "fixedInfoPattern", cap));

		CKINT(acvp_req_set_algo_kdf_108_details(kdf_108, cap));

		/*
		 * Verify that the supported length of the KDF matches the
		 * supported length of the KAS.
		 */
		CKINT_LOG(acvp_req_in_range(supported_length,
					    kdf_108->supported_lengths),
			  "KAS twostep KDF: Value %u is not in allowed range\n",
			  supported_length);
	}

out:
	return ret;
}

int
acvp_req_kas_kdf_twostep_impl(const struct def_algo_kas_kdf_twostepkdf *twostep,
			      unsigned int twostekdf_num,
			      unsigned int supported_length,
			      struct json_object *entry)
{
	struct json_object *ts;
	int ret;

	if (!twostekdf_num)
		return 0;

	ts = json_object_new_object();
	CKNULL(ts, -ENOMEM);
	CKINT(json_object_object_add(entry, "twoStepKdf", ts));

	CKINT(acvp_req_kas_kdf_twostep_def(twostep, twostekdf_num,
					   supported_length, ts));

out:
	return ret;
}

int
acvp_req_kas_kdf_onestep_def(const struct def_algo_kas_kdf_onestepkdf *onestep,
			     struct json_object *os)
{
	struct json_object *tmp;
	unsigned int i;
	int ret;

	/* aux functions */
	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(os, "auxFunctions", tmp));

	for (i = 0; i < onestep->aux_function_num; i++) {
		struct json_object *one;
		const struct def_algo_kas_kdf_onestepkdf_aux *aux_function =
						onestep->aux_function + i;

		one = json_object_new_object();
		CKNULL(one, -ENOMEM);
		CKINT(json_object_array_add(tmp, one));

		CKINT(acvp_req_cipher_to_string(one, aux_function->auxfunc,
				ACVP_CIPHERTYPE_MAC | ACVP_CIPHERTYPE_HASH,
				"auxFunctionName"));

		/* OneStepNoCounter */
		if (aux_function->length) {
			if (aux_function->length > 2048) {
				logger(LOGGER_ERR, LOGGER_C_ANY,
				       "SP800-56C: KAS KDF length maximum is 2048 bits\n");
				ret = -EINVAL;
				goto out;
			}

			CKINT(json_object_object_add(one, "l",
				json_object_new_int((int)aux_function->length)));
		}

		if (aux_function->auxfunc & ACVP_CIPHERTYPE_MAC) {
			CKINT(acvp_req_kas_mac_salt(
				aux_function->mac_salt_method,
				aux_function->saltlen, one));
		}
	}

	CKINT(acvp_req_kas_kdf_fi(onestep->fixed_info_pattern_type,
				  onestep->literal, onestep->fixed_info_encoding,
				  "fixedInfoPattern", os));

out:
	return ret;
}

int
acvp_req_kas_kdf_onestep_impl(const struct def_algo_kas_kdf_onestepkdf *onestep,
			      struct json_object *entry)
{
	struct json_object *os;
	int ret;

	if (!onestep->aux_function_num)
		return 0;

	os = json_object_new_object();
	CKNULL(os, -ENOMEM);
	CKINT(json_object_object_add(entry, "oneStepKdf", os));

	CKINT(acvp_req_kas_kdf_onestep_def(onestep, os));

out:
	return ret;
}

int
acvp_req_kas_mac_method(const struct def_algo_kas_mac_method *mac,
			unsigned int mac_entries, struct json_object *entry)
{
	unsigned int i;
	int ret = 0;
	const char *algo;

	if (!mac_entries) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS: At least one MAC definition required\n");
		return -EINVAL;
	}

	for (i = 0; i < mac_entries; i++) {
		struct json_object *mac_entry;
		const struct def_algo_kas_mac_method *onemac = mac + i;

		/* mac lengths */
		CKINT(acvp_req_cipher_to_name(onemac->mac, ACVP_CIPHERTYPE_MAC,
					      &algo));
		mac_entry = json_object_new_object();
		CKNULL(mac_entry, -ENOMEM);
		CKINT(json_object_object_add(entry, algo, mac_entry));

		if (onemac->key_length < 128 || onemac->key_length > 512) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS MAC method: Key length required to be between 128 and 512\n");
			ret = -EINVAL;
			goto out;
		}
		if (onemac->mac_length < 64 || onemac->mac_length > 512) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS MAC method: MAC length required to be between 64 and 512\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_object_add(mac_entry, "keyLen",
				json_object_new_int((int)onemac->key_length)));
		CKINT(json_object_object_add(mac_entry, "macLen",
				json_object_new_int((int)onemac->mac_length)));
	}

out:
	return ret;
}

int
acvp_req_kas_r3_kc_method(const struct def_algo_kas_r3_kc *kcm,
			  struct json_object *entry)
{
	struct json_object *kcm_entry, *t1;
	int ret;
	bool found = false;

	/* Key confirmation is optional */
	if (!kcm->kc_direction || !kcm->kcrole)
		return 0;

	/* Key convirmation methods */
	kcm_entry = json_object_new_object();
	CKNULL(kcm_entry, -ENOMEM);
	CKINT(json_object_object_add(entry, "keyConfirmationMethod",
				     kcm_entry));

	/* mac method */
	t1 = json_object_new_object();
	CKNULL(t1, -ENOMEM);
	CKINT(json_object_object_add(kcm_entry, "macMethods", t1));
	CKINT(acvp_req_kas_mac_method(kcm->mac, kcm->mac_entries, t1));

	/* key confirmation directions */
	t1 = json_object_new_array();
	CKNULL(t1, -ENOMEM);
	CKINT(json_object_object_add(kcm_entry, "keyConfirmationDirections",
				     t1));
	if (kcm->kc_direction & DEF_ALG_KAS_R3_UNILATERAL) {
		CKINT(json_object_array_add(t1,
					json_object_new_string("unilateral")));
		found = true;
	}
	if (kcm->kc_direction & DEF_ALG_KAS_R3_BILATERAL) {
		CKINT(json_object_array_add(t1,
					json_object_new_string("bilateral")));
		found = true;
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS FFC r3: Unknown key confirmation direction\n");
		ret = -EINVAL;
		goto out;
	}

	/* key confirmation roles */
	found = false;
	t1 = json_object_new_array();
	CKNULL(t1, -ENOMEM);
	CKINT(json_object_object_add(kcm_entry, "keyConfirmationRoles",
				     t1));
	if (kcm->kcrole & DEF_ALG_KAS_R3_PROVIDER) {
		CKINT(json_object_array_add(t1,
					json_object_new_string("provider")));
		found = true;
	}
	if (kcm->kcrole & DEF_ALG_KAS_R3_RECIPIENT) {
		CKINT(json_object_array_add(t1,
					json_object_new_string("recipient")));
		found = true;
	}

	CKNULL_LOG(found, -EINVAL,
		   "KAS FFC r3: Unknown key confirmation direction\n");

out:
	return ret;
}
