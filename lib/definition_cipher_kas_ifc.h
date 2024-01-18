/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_KAS_IFC_H
#define DEFINITION_CIPHER_KAS_IFC_H

#include "definition_cipher_rsa_common.h"
#include "definition_cipher_kas_kdf_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_kas_ifc_keygen {
	/*
	 * Supported Key Generation Methods
	 * Note that AT LEAST one Key Generation Method is required.
	 *
	 * rsakpg1-basic: Private key basic format with a fixed exponent. A
	 *		  fixed public exponent is REQUIRED to be specified.
	 *
	 * rsakpg1-prime-factor: Private key prime factor format with a fixed
	 * 			 exponent. A fixed public exponent is REQUIRED
	 *			 to be specified.
	 *
	 * rsakpg1-crt: Private key CRT format with a fixed exponent. A fixed
	 *		public exponent is REQUIRED to be specified.
	 *
	 * rsakpg2-basic: Private key basic format with a random exponent.
	 *
	 * rsakpg2-prime-factor: Private key prime factor format with a random
	 *			 exponent.
	 *
	 * rsakpg2-crt: Private key CRT format with a random exponent.
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_IFC_KEYGEN_METHOD_MAX_NUM 10
	enum kas_ifc_keygen_method {
		DEF_ALG_KAS_IFC_KEYGEN_METHOD_UNKNOWN,
		DEF_ALG_KAS_IFC_RSAKPG1_BASIC,
		DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,
		DEF_ALG_KAS_IFC_RSAKPG1_CRT,

		DEF_ALG_KAS_IFC_RSAKPG2_BASIC,
		DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR,
		DEF_ALG_KAS_IFC_RSAKPG2_CRT,
	} keygen_method[DEF_ALG_KAS_IFC_KEYGEN_METHOD_MAX_NUM];

	/*
	 * Supported RSA modulo
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_IFC_MODULO_MAX_NUM 10
	enum rsa_modulo rsa_modulo[DEF_ALG_KAS_IFC_MODULO_MAX_NUM];

	/*
	 * The value of the public key exponent e in hex
	 *
	 * required: See requirement as documented for kas_ifc_keygen_method.
	 */
	const char *fixedpubexp;
};

struct def_algo_kts_method {
	/*
	 * The hasl algorithms available to the IUT.
	 *
	 * One or more of the following are allowed
	 * SHA2-224
	 * SHA2-256
	 * SHA2-384
	 * SHA2-512
	 * SHA2-512/224
	 * SHA2-512/256
	 * SHA3-224
	 * SHA3-256
	 * SHA3-384
	 * SHA3-512
	 *
	 * required
	 */
	cipher_t hashalg;

	/*
	 * Does the IUT support a null association data (fixedInfo)?
	 *
	 * required
	 */
	bool supports_null_association_data;

	/*
	 * The pattern used to construct the associated data.
	 *
	 * If a DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL is specified, the literal
	 * must be provided with *literal which is a hex value.
	 *
	 * required: always
	 */
	enum kas_kdf_fixedinfo_pattern associated_data_pattern_type
		[DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN];
	const char *literal;
	enum kas_kdf_fixedinfo_encoding associated_data_pattern_encoding;
};

/******************************************************************************
 * Definition of one given KAS-IFC schema
 ******************************************************************************/
struct def_algo_kas_ifc_schema {
	/*
	 * Key agreement schema defined with this structure instance
	 *
	 * KAS Schemes
	 *
	 *  * KAS1-basic - requires kdfMethod
	 *  * KAS1-Party_V-confirmation - requires kdfMethods, macMethods
	 *  * KAS2-basic - requires kdfMethods
	 *  * KAS2-bilateral-confirmation - requires kdfMethods, macMethods
	 *  * KAS2-Party_U-confirmation - requires kdfMethods, macMethods
	 *  * KAS2-Party_V-confirmation - requires kdfMethods, macMethods
	 *
	 * KTS Schemes
	 *  * KTS-OAEP-basic - requires ktsMethod, macMethods
	 *  * KTS-OAEP-Party_V-confirmation - requires ktsMethod, macMethods
	 *
	 * required: always
	 */
	enum kas_ifc_schema {
		DEF_ALG_KAS_IFC_KAS1_BASIC,
		DEF_ALG_KAS_IFC_KAS1_PARTY_V,

		DEF_ALG_KAS_IFC_KAS2_BASIC,
		DEF_ALG_KAS_IFC_KAS2_BILATERAL_CONFIRMATION,
		DEF_ALG_KAS_IFC_KAS2_PARTY_U,
		DEF_ALG_KAS_IFC_KAS2_PARTY_V,

		DEF_ALG_KAS_IFC_KTS_OAEP_BASIC,
		DEF_ALG_KAS_IFC_KTS_OAEP_PARTY_V,
	} schema;

	/*
	 * KAS IFC role
	 */
#define DEF_ALG_KAS_IFC_INITIATOR (1 << 0)
#define DEF_ALG_KAS_IFC_RESPONDER (1 << 1)
	unsigned int kas_ifc_role;

	/*
	 * Supported KDF Methods for KAS
	 *
	 * required: For KAS methods, at least one KDF method is required
	 */
	const struct def_algo_kas_kdf_onestepkdf onestepkdf;

	const struct def_algo_kas_kdf_twostepkdf *twostepkdf;
	unsigned int twostepkdf_num;

	/*
	 * The KTS method to use when testing KTS schemes.
	 *
	 * required: For KTS methods
	 */
	const struct def_algo_kts_method kts_method;

	/*
	 * One or more MAC definitions
	 *
	 * required: for
	 * DEF_ALG_KAS_IFC_KAS1_PARTY_V
	 * DEF_ALG_KAS_IFC_KAS2_BILATERAL_CONFIRMATION
	 * DEF_ALG_KAS_IFC_KAS2_PARTY_U
	 * DEF_ALG_KAS_IFC_KAS2_PARTY_V
	 * DEF_ALG_KAS_IFC_KTS_OAEP_BASIC
	 * DEF_ALG_KAS_IFC_KTS_OAEP_PARTY_V
	 */
	const struct def_algo_kas_mac_method *mac;
	unsigned int mac_entries;

	/*
	 * The length of the key to derive (using a KDF) or transport (using a
	 * KTS scheme). This value should be large enough to accommodate the
	 * key length used for the MAC algorithms in use for the key confirmation,
	 * ideally the maximum value the IUT can support with their KAS/KTS
	 * implementation. Maximum value (for testing purposes) is 1024.
	 *
	 * Minimum without key confirmation is 128.
	 * Minimum with key confirmation is 136.
	 * Maximum is 1024
	 *
	 * required: always
	 */
	unsigned int length;
};

struct def_algo_kas_ifc_ssc_schema {
	/*
	 * Key agreement schema defined with this structure instance
	 *
	 * KAS Schemes
	 *
	 *  * KAS1
	 *  * KAS2
	 *
	 * required: always
	 */
	enum kas_ifc_ssc_schema {
		DEF_ALG_KAS_IFC_SSC_KAS1,
		DEF_ALG_KAS_IFC_SSC_KAS2,
	} schema;

	/*
	 * KAS IFC role
	 */
#define DEF_ALG_KAS_IFC_INITIATOR (1 << 0)
#define DEF_ALG_KAS_IFC_RESPONDER (1 << 1)
	unsigned int kas_ifc_role;
};

/****************************************************************************
 * SP800-56B KAS-IFC common data data
 ****************************************************************************/
struct def_algo_kas_ifc {
	/*
	 * Prerequisites to KAS IFC
	 * required: always
	 * CMAC
	 * DRBG
	 * ECDSA
	 * HMAC
	 * SHA
	 * KMAC
	 * IKEv1
	 * IKEv2
	 * TLSv1.0/1.1
	 * TLSv1.1
	 * RSA
	 * RSADP
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * Supported KAS IFC Functions
	 *
	 * The following function types MAY be advertised by the ACVP compliant
	 * crypto module:
	 *   * keyPairGen - IUT can perform keypair generation.
	 *   * partialVal - IUT can perform partial public key validation (
	 *     [SP800-56Br2] section 6.4.2.2)
	 *
	 * requred: optional (if not defined, use DEF_ALG_KAS_IFC_UNDEFINED)
	 */
#define DEF_ALG_KAS_IFC_UNDEFINED (1 << 0)
#define DEF_ALG_KAS_IFC_KEYPAIRGEN (1 << 1)
#define DEF_ALG_KAS_IFC_PARTIALVAL (1 << 2)
#define DEF_ALG_KAS_IFC_PARITALVAL DEF_ALG_KAS_IFC_PARTIALVAL
#define DEF_ALG_KAS_IFC_SSC (1 << 3)
	unsigned int function;

	/*
	 * The identifier of the IUT - this is a hex string
	 * required: always except for DEF_ALG_KAS_IFC_SSC
	 */
	const char *iut_identifier;

	/*
	 * Supported key agreement schemes. An array of one or more key
	 * agreement schemes can be defined. There must be one definition
	 * per requested scheme.
	 *
	 * required: always except for DEF_ALG_KAS_IFC_SSC
	 */
	const struct def_algo_kas_ifc_schema *schema;
	/* Number of schemas */
	unsigned int schema_num;

	/*
	 * Supported key agreement schemes. An array of one or more key
	 * agreement schemes can be defined. There must be one definition
	 * per requested scheme.
	 *
	 * required: always for DEF_ALG_KAS_IFC_SSC
	 */
	const struct def_algo_kas_ifc_ssc_schema *ssc_schema;
	/* Number of schemas */
	unsigned int ssc_schema_num;

	/*
	 * Supported Key Generation Methods
	 * Note that AT LEAST one Key Generation Method is required.
	 */
	const struct def_algo_kas_ifc_keygen keygen;

	/*
	 * IUT supported hash of the shared secret. This is optional
	 * to accommodate clients with the inability to return `z` in clear.
	 *
	 * Any hash (SHA-1 through SHA-3) may be specified. Note, the strength
	 * of the hash operation must be at least as strong as the selected
	 * curve. E.g. NIST P-521 will not work with SHA-256.
	 *
	 * required: optional, only applicable to DEF_ALG_KAS_IFC_SSC
	 */
	cipher_t hash_z;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_IFC_H */
