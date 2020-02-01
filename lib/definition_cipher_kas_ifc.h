/*
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

#ifndef DEFINITION_CIPHER_KAS_IFC_H
#define DEFINITION_CIPHER_KAS_IFC_H

#include "definition_cipher_rsa_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * IUTs SHALL be capable of specifying how the FixedInfo is constructed
 * for the KAS/KTS negotiation.
 */
enum kas_ifc_fixedinfo_pattern {
	/* Use the specified hex within value. */
	DEF_ALG_KAS_IFC_FI_PATTERN_LITERAL,

	/* uPartyId { || dkmNonce } { || c } */
	DEF_ALG_KAS_IFC_FI_PATTERN_U_PARTY_INFO,

	/* vPartyId { || dkmNonce } { || c } */
	DEF_ALG_KAS_IFC_FI_PATTERN_V_PARTY_INFO,

	/* Random value chosen by ACVP server to represent the context. */
	DEF_ALG_KAS_IFC_FI_PATTERN_CONTEXT,

	/* Random value chosen by ACVP server to represent the algorithmId. */
	DEF_ALG_KAS_IFC_FI_PATTERN_ALGORITHM_ID,

	/* Random value chosen by ACVP server to represent the label. */
	DEF_ALG_KAS_IFC_FI_PATTERN_LABEL,

	/*
	 * Concatenation of multiple entries: example (Note that party U is the
	 * server in this case "434156536964", party V is the IUT "a1b2c3d4e5").
	 * The example of "literal[123456789CAFECAFE]||uPartyInfo||vPartyInfo" is
	 * evaluated as "123456789CAFECAFE434156536964a1b2c3d4e5".
	 */
	DEF_ALG_KAS_IFC_FI_PATTERN_CONCATENATION,
};

enum kas_ifc_fixedinfo_encoding {
	DEF_ALG_KAS_IFC_FI_ENCODING_CONCATENATION,
	/* TODO: ASN.1 not yet supported by ACVP server */
	//DEF_ALG_KAS_IFC_FI_ENCODING_ASN1,
};

struct def_algo_kas_ifc_onestepkdf_aux {
	/*
	 * Used auxiliary function
	 *
	 * Allowed values for onestep:
	 *	"SHA2-224"
	 *	"SHA2-256"
	 *	"SHA2-384"
	 *	"SHA2-512"
	 *	"SHA2-512/224"
	 *	"SHA2-512/256"
	 *	"SHA3-224"
	 *	"SHA3-256"
	 *	"SHA3-384"
	 *	"SHA3-512"
	 *	"KMAC-128"
	 *	"KMAC-256"
	 *
	 * Allowed values for twostep:
	 *	"CMAC-AES128"
	 *	"CMAC-AES192"
	 *	"CMAC-AES256"
	 *	"HMAC-SHA-1"
	 *	"HMAC-SHA2-224"
	 *	"HMAC-SHA2-256"
	 *	"HMAC-SHA2-384"
	 *	"HMAC-SHA2-512"
	 *	"HMAC-SHA2-512/224"
	 *	"HMAC-SHA2-512/256"
	 *	"HMAC-SHA3-224"
	 *	"HMAC-SHA3-256"
	 *	"HMAC-SHA3-384"
	 *	"HMAC-SHA3-512"
	 *
	 * required: always
	 */
	cipher_t auxfunc;

	/*
	 * How the salt is determined (default means a set of zero bytes)
	 *
	 * required: if auxfunc points to a MAC method
	 */
#define DEF_ALG_KAS_IFC_MACSALTMETHOD_DEFAULT	(1<<0)
#define DEF_ALG_KAS_IFC_MACSALTMETHOD_RANDOM	(1<<1)
	unsigned int macsaltmethod;
};

/*
 * oneStepKdf: Indicates the IUT will be testing key derivation using
 *	       the SP800-56Cr1 OneStepKdf.
 */
struct def_algo_kas_ifc_onestepkdf {
	/*
	 * Auxiliary function to be used with KDF
	 *
	 * This is an array of one or more function definitions with the
	 * array numbers defined by aux_function_num.
	 *
	 * required: always
	 */
	const struct def_algo_kas_ifc_onestepkdf_aux aux_function;
	unsigned int aux_function_num;

	/*
	 * The pattern and encoding used for fixedInfo construction.
	 *
	 * required: always
	 */
	enum kas_ifc_fixedinfo_pattern fixed_info_pattern_type;
	const char *fixedinfo_pattern;
	enum kas_ifc_fixedinfo_encoding fixed_info_encoding;
};

/*
 * twoStepKdf: Indicates the IUT will be testing key derivation using
 *	       the SP800-56Cr1 TwoStepKdf.
 */
struct def_algo_kas_ifc_twostepkdf {
	unsigned int mac_salt_method;
};

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
	enum kas_ifc_keygen_method {
		DEF_ALG_KAS_IFC_RSAKPG1_BASIC,
		DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,
		DEF_ALG_KAS_IFC_RSAKPG1_CRT,

		DEF_ALG_KAS_IFC_RSAKPG2_BASIC,
		DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR,
		DEF_ALG_KAS_IFC_RSAKPG2_CRT,
	} keygen_method;

	/*
	 * Supported RSA modulo
	 *
	 * required: always
	 */
	enum rsa_modulo rsa_modulo;

	/*
	 * The value of the public key exponent e in hex
	 *
	 * required: See requirement as documented for kas_ifc_keygen_method.
	 */
	const char *fixedpubexp;
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
	 * Supported Key Generation Methods
	 * Note that AT LEAST one Key Generation Method is required.
	 */
	const struct def_algo_kas_ifc_keygen *keygen;

	/*
	 * Number of key generation definitions. There must be one or more
	 * key generation definitions.
	 * Note, the keygen pointer above must point to the first
	 * entry of an array of key generation definitions!
	 */
	unsigned int keygen_num;

	/*
	 * Supported KDF Methods
	 *
	 * required: For KAS methods, at least one KDF method is required
	 */
	const struct def_algo_kas_ifc_onestepkdf *onestekdf;
	unsigned int onestekdf_num;

	const struct def_algo_kas_ifc_twostepkdf *twostekdf;
	unsigned int twostekdf_num;
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
#define DEF_ALG_KAS_IFC_UNDEFINED	(1<<0)
#define DEF_ALG_KAS_IFC_KEYPAIRGEN	(1<<1)
#define DEF_ALG_KAS_IFC_PARITALVAL	(1<<2)
	unsigned int function;

	/*
	 * Supported key agreement schemes. An array of one or more key
	 * agreement schemes can be defined. There must be one definition
	 * per requested scheme.
	 *
	 * required: always
	 */
	const struct def_algo_kas_ifc_schema *schema;

	/*
	 * Number of schemes. There must be one or more schema definitions.
	 * Note, the scheme pointer above must point to the first
	 * entry of an array of schemes!
	 */
	unsigned int scheme_num;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_IFC_H */
