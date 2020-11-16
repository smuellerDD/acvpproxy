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

#ifndef DEFINITION_CIPHER_KAS_FFC_R3_H
#define DEFINITION_CIPHER_KAS_FFC_R3_H

#include "definition_common.h"
#include "definition_cipher_kas_kdf_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct def_algo_kas_ffc_r3_schema {
	/*
	 * Supported KAS FCC Schemes
	 *
	 * The following schemes may be advertised by the ACVP compliant crypto
	 * module:
	 *
	 * o  dhHybrid1
	 *
	 * o  MQV2
	 *
	 * o  dhEphem - KeyConfirmation not supported.
	 *
	 * o  dhHybridOneFlow
	 *
	 * o  MQV1
	 *
	 * o  dhOneFlow - Can only provide unilateral key confirmation party V
	 *    to party U.
	 *
	 * o  dhStatic
	 *
	 * required: always
	 */
	enum kas_ffc_schema {
		DEF_ALG_KAS_FFC_R3_DH_HYBRID_1,
		DEF_ALG_KAS_FFC_R3_MQV2,
		DEF_ALG_KAS_FFC_R3_DH_EPHEM,
		DEF_ALG_KAS_FFC_R3_DH_HYBRID_ONE_FLOW,
		DEF_ALG_KAS_FFC_R3_MQV1,
		DEF_ALG_KAS_FFC_R3_DH_ONE_FLOW,
		DEF_ALG_KAS_FFC_R3_DH_STATIC,
	} schema;

	/*
	 * KAS FFC DH role
	 */
#define DEF_ALG_KAS_FFC_R3_INITIATOR		(1<<0)
#define DEF_ALG_KAS_FFC_R3_RESPONDER		(1<<1)
	unsigned int kas_ffc_role;

	/*
	 * Supported KDF Methods
	 *
	 * required: For KAS methods, at least one KDF method is required
	 *	     except for DEF_ALG_KAS_FFC_R3_SSC
	 */
	const struct def_algo_kas_kdf_onestepkdf onestepkdf;

	const struct def_algo_kas_kdf_twostepkdf *twostepkdf;
	unsigned int twostepkdf_num;

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
 * KAS FFC common data
 ****************************************************************************/
struct def_algo_kas_ffc_r3 {
	/*
	 * Prerequisites to KAS FFC
	 * required: always
	 * CCM
	 * CMAC
	 * DRBG
	 * DSA
	 * HMAC
	 * KMAC
	 * SHA
	 * SP800-108
	 * SafePrimes
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * KAS FFC function type
	 *
	 * * key pair generation
	 * * partial validation
	 * * full validation
	 * * shared secret computation
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_FFC_R3_KEYPAIRGEN		(1<<0)
#define DEF_ALG_KAS_FFC_R3_PARTIALVAL		(1<<1)
#define DEF_ALG_KAS_FFC_R3_FULLVAL		(1<<2)
#define DEF_ALG_KAS_FFC_R3_SSC			(1<<3)
	unsigned int kas_ffc_function;

	/*
	 * The identifier of the IUT - this is a hex string
	 * required: always except for DEF_ALG_KAS_FFC_R3_SSC
	 */
	const char *iut_identifier;

	/*
	 * Array of supported key agrement schemes each having their own
	 * capabilities
	 * required: at least one
	 */
	const struct def_algo_kas_ffc_r3_schema *schema;
	/* Number of schemas */
	unsigned int schema_num;

	/*
	 * One or more of the following ciphers combined with OR:
	 *
	 * ACVP_DH_MODP_2048
	 * ACVP_DH_MODP_3072
	 * ACVP_DH_MODP_4096
	 * ACVP_DH_MODP_6144
	 * ACVP_DH_MODP_8192
	 * ACVP_DH_FFDHE_2048
	 * ACVP_DH_FFDHE_3072
	 * ACVP_DH_FFDHE_4096
	 * ACVP_DH_FFDHE_6144
	 * ACVP_DH_FFDHE_8192
	 * ACVP_DH_FB
	 * ACVP_DH_FC
	 */
	cipher_t domain_parameter;

	/*
	 * IUT supported hash of the shared secret. This is optional
	 * to accommodate clients with the inability to return `z` in clear.
	 *
	 * Any hash (SHA-1 through SHA-3) may be specified. Note, the strength
	 * of the hash operation must be at least as strong as the selected
	 * domain parameters. E.g. NIST MODP-4096 will not work with SHA-256.
	 *
	 * required: optional, only applicable to DEF_ALG_KAS_ECC_R3_SSC
	 */
	cipher_t hash_z;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_FFC_R3_H */
