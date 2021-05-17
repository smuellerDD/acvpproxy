/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_KAS_KDF_COMMON_H
#define DEFINITION_CIPHER_KAS_KDF_COMMON_H

#include "definition_cipher_kdf_108.h"
#include "json-c/json.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN 10

enum kdf_spec {
	DEF_ALG_KDF_SP800_56Crev1 = 0,
	DEF_ALG_KDF_SP800_56Crev2
};

/*
 * IUTs SHALL be capable of specifying how the FixedInfo is constructed
 * for the KAS/KTS negotiation.
 */
enum kas_kdf_fixedinfo_pattern {
	/* Use the specified hex within value. */
	DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL = 1,

	/* uPartyId { || dkmNonce } { || c } */
	DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,

	/* vPartyId { || dkmNonce } { || c } */
	DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,

	/* Random value chosen by ACVP server to represent the context. */
	DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT,

	/* Random value chosen by ACVP server to represent the algorithmId. */
	DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID,

	/* Random value chosen by ACVP server to represent the label. */
	DEF_ALG_KAS_KDF_FI_PATTERN_LABEL
};

enum kas_kdf_fixedinfo_encoding {
	DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	/* TODO: ASN.1 not yet supported by ACVP server */
	//DEF_ALG_KAS_KDF_FI_ENCODING_ASN1,
};

struct def_algo_kas_kdf_onestepkdf_aux {
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
#define DEF_ALG_KAS_KDF_MAC_SALT_UNDEFINED (0)
	/* All bytes are zero bytes */
#define DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT (1 << 0)
	/* Random salt */
#define DEF_ALG_KAS_KDF_MAC_SALT_RANDOM (1 << 1)
	unsigned int mac_salt_method;

	/*
	 * Length of the salt value
	 *
	 * required: optional
	 */
	int saltlen;
};

/*
 * oneStepKdf: Indicates the IUT will be testing key derivation using
 *	       the SP800-56Cr1 OneStepKdf.
 */
struct def_algo_kas_kdf_onestepkdf {
	/*
	 * Auxiliary function to be used with KDF
	 *
	 * This is an array of one or more function definitions with the
	 * array numbers defined by aux_function_num.
	 *
	 * required: always
	 */
	const struct def_algo_kas_kdf_onestepkdf_aux *aux_function;
	unsigned int aux_function_num;

	/*
	 * The pattern and encoding used for fixedInfo construction.
	 *
	 * If a DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL is specified, the literal
	 * must be provided with *literal which is a hex value.
	 *
	 * required: always
	 */
	enum kas_kdf_fixedinfo_pattern
		fixed_info_pattern_type[DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN];
	const char *literal;
	enum kas_kdf_fixedinfo_encoding fixed_info_encoding;
};

/*
 * twoStepKdf: Indicates the IUT will be testing key derivation using
 *	       the SP800-56Cr1 TwoStepKdf.
 */
struct def_algo_kas_kdf_twostepkdf {
	/*
	 * How the salt is determined
	 *
	 * required: always for mac based auxiliary functions, otherwise
	 * optional
	 */
#define DEF_ALG_KAS_KDF_MAC_SALT_UNDEFINED (0)
	/* All bytes are zero bytes */
#define DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT (1 << 0)
	/* Random salt */
#define DEF_ALG_KAS_KDF_MAC_SALT_RANDOM (1 << 1)
	unsigned int mac_salt_method;

	/*
	 * Length of the salt value
	 *
	 * required: optional
	 */
	int saltlen;

	/*
	 * The pattern and encoding used for fixedInfo construction.
	 *
	 * If a DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL is specified, the literal
	 * must be provided with *literal which is a hex value.
	 *
	 * required: always
	 */
	enum kas_kdf_fixedinfo_pattern
		fixed_info_pattern_type[DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN];
	const char *literal;
	enum kas_kdf_fixedinfo_encoding fixed_info_encoding;

	/*
	 * Definition of the KDF
	 *
	 * Fill in the entire data structure except the prerequisites.
	 *
	 * required: always
	 */
	const struct def_algo_kdf_108 kdf_108;
};

/*
 * Mac Methods
 */
struct def_algo_kas_mac_method {
	/*
	 * Supported MAC methods
	 *
	 * Use one of the following
	 *
	 * CMAC
	 * HMAC-SHA2-224
	 * HMAC-SHA2-256
	 * HMAC-SHA2-384
	 * HMAC-SHA2-512
	 * HMAC-SHA2-512224
	 * HMAC-SHA2-512256
	 * HMAC-SHA3-224
	 * HMAC-SHA3-256
	 * HMAC-SHA3-384
	 * HMAC-SHA3-512
	 * KMAC-128
	 * KMAC-256
	 *
	 * required: always
	 */
	cipher_t mac;

	/*
	 * The amount of bits from the DKM to pass into the key confirmation
	 * MAC function.
	 *
	 * Valid values: 128 - 512. Note that the DKM is REQUIRED to have at least
	 * 8 bits available after subtracting the key_length specified.
	 *
	 * For CMAC, the value must be either 128, 192, 256.
	 *
	 * required: always
	 */
	unsigned int key_length;

	/*
	 * The amount of bits to use as the tag from the MAC function.
	 *
	 * Valid values: 64 - 512
	 *
	 * required: always
	 */
	unsigned int mac_length;
};

struct def_algo_kas_r3_kc {
	/*
	 * The directions in which key confirmation is supported
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_R3_UNILATERAL (1 << 0)
#define DEF_ALG_KAS_R3_BILATERAL (1 << 1)
	unsigned int kc_direction;

	/*
	 * The role(s) the IUT is to act as for Key Confirmation.
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_R3_PROVIDER (1 << 0)
#define DEF_ALG_KAS_R3_RECIPIENT (1 << 1)
	unsigned int kcrole;

	/*
	 * One or more MAC definitions
	 * required: at least one definition
	 */
	const struct def_algo_kas_mac_method *mac;
	unsigned int mac_entries;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_KDF_COMMON_H */
