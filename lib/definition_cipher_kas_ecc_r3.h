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

#ifndef DEFINITION_CIPHER_KAS_ECC_R3_H
#define DEFINITION_CIPHER_KAS_ECC_R3_H

#include "definition_common.h"
#include "definition_cipher_kas_kdf_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct def_algo_kas_ecc_r3_schema {
	/*
	 * Supported KAS FCC Schemes
	 *
	 * The following schemes may be advertised by the ACVP compliant crypto
	 * module:
	 *
	 * o  ephemeralUnified - keyConfirmation not supported
	 *
	 * o  fullMqv
	 *
	 * o  fullUnified
	 *
	 * o  onePassDh - Can only provide unilateral key confirmation party V
	 *		  to party U.
	 *
	 * o  onePassMqv
	 *
	 * o  onePassUnified
	 *
	 * o  staticUnified
	 *
	 * required: always
	 */
	enum kas_ecc_schema {
		DEF_ALG_KAS_ECC_R3_EPHEMERAL_UNIFIED,
		DEF_ALG_KAS_ECC_R3_FULL_MQV,
		DEF_ALG_KAS_ECC_R3_FULL_UNIFIED,
		DEF_ALG_KAS_ECC_R3_ONE_PASS_DH,
		DEF_ALG_KAS_ECC_R3_ONE_PASS_MQV,
		DEF_ALG_KAS_ECC_R3_ONE_PASS_UNIFIED,
		DEF_ALG_KAS_ECC_R3_STATIC_UNIFIED,
	} schema;

	/*
	 * KAS ECC DH role
	 */
#define DEF_ALG_KAS_ECC_R3_INITIATOR		(1<<0)
#define DEF_ALG_KAS_ECC_R3_RESPONDER		(1<<1)
	unsigned int kas_ecc_role;

	/*
	 * Supported KDF Methods
	 *
	 * required: For KAS methods, at least one KDF method is required
	 *	     except for DEF_ALG_KAS_ECC_R3_SSC
	 */
	const struct def_algo_kas_kdf_onestepkdf onestekdf;

	const struct def_algo_kas_kdf_twostepkdf *twostekdf;
	unsigned int twostekdf_num;

	/*
	 * The key confirmation capabilities when supported for the schema.
	 *
	 * required: optional
	 *
	 * KC is not to be configured, leave all entries with zero
	 */
	struct def_algo_kas_r3_kc key_confirmation_method;

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
	 * required: always except for DEF_ALG_KAS_FFC_R3_SSC
	 */
	unsigned int length;
};

/****************************************************************************
 * KAS ECC common data
 ****************************************************************************/
struct def_algo_kas_ecc_r3 {
	/*
	 * Prerequisites to KAS ECC
	 * required: always
	 * CMAC
	 * DRBG
	 * ECDSA
	 * HMAC
	 * KMAC
	 * SHA
	 * SP800-108
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * KAS ECC function type
	 *
	 * * key pair generation
	 * * partial validation
	 * * full validation
	 * * shared secret computation
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_ECC_R3_KEYPAIRGEN		(1<<0)
#define DEF_ALG_KAS_ECC_R3_PARTIALVAL		(1<<1)
#define DEF_ALG_KAS_ECC_R3_FULLVAL		(1<<2)
#define DEF_ALG_KAS_ECC_R3_SSC			(1<<3)
	unsigned int kas_ecc_function;

	/*
	 * The identifier of the IUT - this is a hex string
	 * required: always except for DEF_ALG_KAS_ECC_R3_SSC
	 */
	const char *iut_identifier;

	/*
	 * Array of supported key agrement schemes each having their own
	 * capabilities
	 * required: at least one except when DEF_ALG_KAS_ECC_R3_SSC is selected
	 */
	const struct def_algo_kas_ecc_r3_schema *schema;
	/* Number of schemas */
	unsigned int schema_num;

	/*
	 * IUT supported domain parameter generation methods.
	 *
	 * One or more of the following ciphers combined with OR:
	 *
	 * P-192
	 * P-224
	 * P-256
	 * P-384
	 * P-521
	 * K-163
	 * K-223
	 * K-283
	 * K-409
	 * K-571
	 * B-163
	 * B-233
	 * B-283
	 * B-409
	 * B-571
	 */
	cipher_t domain_parameter;

	/*
	 * IUT supported hash of the shared secret. This is optional
	 * to accommodate clients with the inability to return `z` in clear.
	 *
	 * Any hash (SHA-1 through SHA-3) may be specified. Note, the strength
	 * of the hash operation must be at least as strong as the selected
	 * curve. E.g. NIST P-521 will not work with SHA-256.
	 *
	 * required: optional, only applicable to DEF_ALG_KAS_ECC_R3_SSC
	 */
	cipher_t hash_z;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_ECC_R3_H */
