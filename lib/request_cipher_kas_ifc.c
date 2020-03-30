/* JSON request generator for KAS IFC (SP800-56B rev. 2)
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

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

static int
acvp_req_kas_ifc_keygen_method(const struct def_algo_kas_ifc_keygen *keygen,
			       struct json_object *entry)
{
	struct json_object *tmp, *tmp2;
	unsigned int i;
	int ret;

	switch (keygen->keygen_method) {
	case DEF_ALG_KAS_IFC_RSAKPG1_BASIC:
		CKNULL_LOG(keygen->fixedpubexp, -EINVAL,
			   "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG1_BASIC requires fixed public exponent\n");
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg1-basic", tmp));
		break;
	case DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR:
		CKNULL_LOG(keygen->fixedpubexp, -EINVAL,
			   "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR requires fixed public exponent\n");
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg1-prime-factor",
					     tmp));
		break;
	case DEF_ALG_KAS_IFC_RSAKPG1_CRT:
		CKNULL_LOG(keygen->fixedpubexp, -EINVAL,
			   "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG1_CRT requires fixed public exponent\n");
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg1-crt", tmp));
		break;
	case DEF_ALG_KAS_IFC_RSAKPG2_BASIC:
		if (keygen->fixedpubexp) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG2_BASIC does not require fixed public exponent\n");
			ret = -EINVAL;
			goto out;
		}
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg2-basic", tmp));
		break;
	case DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR:
		if (keygen->fixedpubexp) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR does not require fixed public exponent\n");
			ret = -EINVAL;
			goto out;
		}
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg2-prime-factor",
					     tmp));
		break;
	case DEF_ALG_KAS_IFC_RSAKPG2_CRT:
		if (keygen->fixedpubexp) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: DEF_ALG_KAS_IFC_RSAKPG2_CRT does not require fixed public exponent\n");
			ret = -EINVAL;
			goto out;
		}
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(entry, "rsakpg2-crt", tmp));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS IFC: No applicable entry for keygen method found\n");
		ret = -EINVAL;
		goto out;
	}

	tmp2 = json_object_new_array();
	CKNULL(tmp2, -ENOMEM);
	CKINT(json_object_object_add(tmp, "modulo", tmp2));
	for (i = 0; i < DEF_ALG_KAS_IFC_MODULO_MAX_NUM; i ++) {
		if (keygen->rsa_modulo[i] == DEF_ALG_RSA_MODULO_UNDEF)
			break;

		switch (keygen->rsa_modulo[i]) {
		case DEF_ALG_RSA_MODULO_2048:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(2048)));
			break;
		case DEF_ALG_RSA_MODULO_3072:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(3072)));
			break;
		case DEF_ALG_RSA_MODULO_4096:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(4096)));
			break;
		case DEF_ALG_RSA_MODULO_5120:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(5120)));
			break;
		case DEF_ALG_RSA_MODULO_6144:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(6144)));
			break;
		case DEF_ALG_RSA_MODULO_7168:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(7168)));
			break;
		case DEF_ALG_RSA_MODULO_8192:
			CKINT(json_object_array_add(tmp2,
						    json_object_new_int(8192)));
			break;
		case DEF_ALG_RSA_MODULO_UNDEF:
		case DEF_ALG_RSA_MODULO_1024:
		default:
			logger(LOGGER_WARN, LOGGER_C_ANY,
			"Unknown RSA modulo definition\n");
			return -EINVAL;
		}
	}

	if (keygen->fixedpubexp) {
		CKINT(json_object_object_add(tmp, "fixedPublicExponent",
				json_object_new_string(keygen->fixedpubexp)));
	}

out:
	return ret;
}

static int
acvp_req_kas_ifc_kts_method(const struct def_algo_kts_method *kts_method,
			    struct json_object *entry)
{
	int ret;

	CKINT(acvp_req_cipher_to_array(entry, kts_method->hashalg,
				       ACVP_CIPHERTYPE_HASH,
				       "hashAlgs"));
	CKINT(json_object_object_add(entry, "supportsNullAssociatedData",
			json_object_new_boolean(
				kts_method->supports_null_association_data)));
	CKINT(acvp_req_kas_kdf_fi(kts_method->associated_data_pattern_type,
				  kts_method->literal,
				  kts_method->associated_data_pattern_encoding,
				  entry));

out:
	return ret;
}

static int
acvp_req_kas_ifc_schema(const struct def_algo_kas_ifc_schema *schema,
			struct json_object *entry)
{
	struct json_object *tmp, *schema_entry;
	unsigned int i;
	int ret;
	bool found = false;

	schema_entry = json_object_new_object();
	CKNULL(schema_entry, -ENOMEM);

	switch (schema->schema) {
	case DEF_ALG_KAS_IFC_KAS1_BASIC:
		CKINT(json_object_object_add(entry, "KAS1-basic",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KAS1_PARTY_V:
		CKINT(json_object_object_add(entry, "KAS1-Party_V-confirmation",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KAS2_BASIC:
		CKINT(json_object_object_add(entry, "KAS2-basic",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KAS2_BILATERAL_CONFIRMATION:
		CKINT(json_object_object_add(entry, "KAS2-bilateral-confirmation",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KAS2_PARTY_U:
		CKINT(json_object_object_add(entry, "KAS2-Party_U-confirmation",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KAS2_PARTY_V:
		CKINT(json_object_object_add(entry, "KAS2-Party_V-confirmation",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KTS_OAEP_BASIC:
		CKINT(json_object_object_add(entry, "KTS-OAEP-basic",
					     schema_entry));
		break;
	case DEF_ALG_KAS_IFC_KTS_OAEP_PARTY_V:
		CKINT(json_object_object_add(entry,
					     "KTS-OAEP-Party_V-confirmation",
					     schema_entry));
		break;
	default:
		ACVP_JSON_PUT_NULL(schema_entry);
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS IFC: No applicable entry for schema found\n");
		ret = -EINVAL;
		goto out;
	}

	/* kasRole */
	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(schema_entry, "kasRole", tmp));
	if (schema->kas_ifc_role & DEF_ALG_KAS_IFC_INITIATOR) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("initiator")));
		found = true;
	}
	if (schema->kas_ifc_role & DEF_ALG_KAS_IFC_RESPONDER) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("responder")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS IFC: No applicable entry for kas_ifc_role found\n");

	/* keyGenerationMethods */
	if (schema->keygen_num > 0) {
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(schema_entry,
					     "keyGenerationMethods", tmp));
		for (i = 0; i < schema->keygen_num; i++) {
			const struct def_algo_kas_ifc_keygen *keygen =
							schema->keygen + i;

			CKINT(acvp_req_kas_ifc_keygen_method(keygen, tmp));
		}
	}

	/* kdfMethods or ktsMethods */
	switch (schema->schema) {

	/* Key configurmation */
	case DEF_ALG_KAS_IFC_KAS1_PARTY_V:
	case DEF_ALG_KAS_IFC_KAS2_BILATERAL_CONFIRMATION:
	case DEF_ALG_KAS_IFC_KAS2_PARTY_U:
	case DEF_ALG_KAS_IFC_KAS2_PARTY_V:
		if (schema->length < 136) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: KAS KDF length minimum without KC is 128 bits\n");
			ret = -EINVAL;
			goto out;
		}
		/* Require MAC methods definition for key confirmation */
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(schema_entry, "macMethods", tmp));
		CKINT(acvp_req_kas_mac_method(schema->mac, schema->mac_entries,
					      tmp));
		/* FALLTHROUGH */

	/* No key confirmation */
	case DEF_ALG_KAS_IFC_KAS1_BASIC:
	case DEF_ALG_KAS_IFC_KAS2_BASIC:
		if (schema->length < 128) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: KAS KDF length minimum without KC is 128 bits\n");
			ret = -EINVAL;
			goto out;
		}
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(schema_entry, "kdfMethods", tmp));
		CKINT(acvp_req_kas_kdf_onestep_impl(&schema->onestekdf, tmp));
		CKINT(acvp_req_kas_kdf_twostep_impl(schema->twostekdf,
						    schema->twostekdf_num,
						    schema->length, tmp));
		break;

	/* Key configurmation */
	case DEF_ALG_KAS_IFC_KTS_OAEP_BASIC:
	case DEF_ALG_KAS_IFC_KTS_OAEP_PARTY_V:
		if (schema->length < 136) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "KAS IFC: KAS KDF length minimum without KC is 128 bits\n");
			ret = -EINVAL;
			goto out;
		}
		/* Require MAC methods definition */
		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(schema_entry, "macMethods", tmp));
		CKINT(acvp_req_kas_mac_method(schema->mac, schema->mac_entries,
					      tmp));

		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(schema_entry, "ktsMethod", tmp));
		CKINT(acvp_req_kas_ifc_kts_method(&schema->kts_method, tmp));
		break;
	default:
		ACVP_JSON_PUT_NULL(tmp);
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS IFC: unknown schema found\n");
		ret = -EINVAL;
		goto out;
	}

	if (schema->length > 1024) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "KAS IFC: KAS KDF length maximum is 1024 bits\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(json_object_object_add(schema_entry, "l",
				     json_object_new_int((int)schema->length)));

out:
	return ret;
}

static int
_acvp_req_set_algo_kas_ifc(const struct def_algo_kas_ifc *kas_ifc,
			   const struct acvp_test_deps *deps,
			   struct json_object *entry, bool full,
			   bool publish)
{
	const struct def_algo_kas_ifc_schema *schema = kas_ifc->schema;
	struct json_object *tmp;
	unsigned int i;
	int ret;
	bool found = false;

	CKNULL_LOG(kas_ifc->schema_num, -EINVAL,
		   "KAS IFC: At least one schema definition required\n");

	CKINT(acvp_req_gen_prereq(kas_ifc->prereqvals,
				  kas_ifc->prereqvals_num, deps, entry,
				  publish));

	/*
	 * TODO: fix after clarifying the seemingly inconsistent specification
	 * as outlined in issue 814
	 */
	if (schema->schema == DEF_ALG_KAS_IFC_KTS_OAEP_BASIC ||
	    schema->schema == DEF_ALG_KAS_IFC_KTS_OAEP_PARTY_V) {
		CKINT(json_object_object_add(entry, "algorithm",
					json_object_new_string("KTS-IFC")));
	} else {
		CKINT(json_object_object_add(entry, "algorithm",
					json_object_new_string("KAS-IFC")));
	}


	CKINT(acvp_req_add_revision(entry, "Sp800-56Br2"));

	if (!full)
		goto out;

	tmp = json_object_new_array();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "function", tmp));
	if (kas_ifc->function & DEF_ALG_KAS_IFC_KEYPAIRGEN) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("keyPairGen")));
		found = true;
	}
	if (kas_ifc->function & DEF_ALG_KAS_IFC_PARITALVAL) {
		CKINT(json_object_array_add(tmp,
					json_object_new_string("partialVal")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "KAS IFC: No applicable entry for function found\n");

	CKNULL_LOG(kas_ifc->iut_identifier, -EINVAL,
		   "KAS IFC: IUT identifier missing");
	CKINT(json_object_object_add(entry, "iutId",
			json_object_new_string(kas_ifc->iut_identifier)));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_object_add(entry, "scheme", tmp));

	for (i = 0; i < kas_ifc->schema_num; i++) {
		schema = kas_ifc->schema + i;
		CKINT(acvp_req_kas_ifc_schema(schema, tmp));
	}

out:
	return ret;
}

int acvp_req_set_prereq_kas_ifc(const struct def_algo_kas_ifc *kas_ifc,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_kas_ifc(kas_ifc, deps, entry, false, publish);
}

int acvp_req_set_algo_kas_ifc(const struct def_algo_kas_ifc *kas_ifc,
			      struct json_object *entry)
{
	return _acvp_req_set_algo_kas_ifc(kas_ifc, NULL, entry, true, false);
}
