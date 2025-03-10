/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_KAS_FFC_H
#define DEFINITION_CIPHER_KAS_FFC_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parameter set to be used for FFC operation:
 *
 *   fb: Len p - 2048, Len q - 224, min hash len - 224, min keySize - 112,
 *   min macSize - 64
 *
 *   fc: Len p - 2048, Len q - 256, min hash len - 256, min keySize - 128,
 *   min macSize - 64
 */
enum kas_ffc_paramset {
	DEF_ALG_KAS_FFC_FB,
	DEF_ALG_KAS_FFC_FC,
};

/*
 * Supported KDF options
 */
#define DEF_ALG_KAS_FFC_CONCATENATION (1 << 0)
#define DEF_ALG_KAS_FFC_ASN1 (1 << 1)

/****************************************************************************
 * KAS FFC data for no KDF and no key confirmation
 ****************************************************************************/
struct def_algo_kas_ffc_nokdfnokc {
	/*
	 * Parameter set for the KAS FFC operation
	 *
	 * required: always
	 */
	enum kas_ffc_paramset kas_ffc_paramset;

	/*
	 * One or more ORed cipher definitions covered by the ACVP_HASHMASK
	 *
	 * required: always
	 */
	cipher_t hashalg;
};

/****************************************************************************
 * KAS FFC data for KDF and no key confirmation
 ****************************************************************************/
struct def_algo_kas_ffc_kdfnokc {
	/*
	 * Parameter set for the KAS FFC operation
	 *
	 * required: always
	 */
	enum kas_ffc_paramset kas_ffc_paramset;

	/*
	 * One or more ORed cipher definitions covered by the ACVP_HASHMASK
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * One of the following:
	 *
	 * ACVP_CCM
	 * ACVP_AESCMAC
	 * ACVP_HMACSHA2_...
	 *
	 * required: always
	 */
	cipher_t mac;

	/*
	 * Key length supported by the MAC in bits. For AES-based MACs this
	 * value is limited to 128, 192 and 256 bits. For HMAC-based MACs,
	 * this value is allowed to be between 8 and 524288 bits.
	 *
	 * required: always
	 */
	int keylen[DEF_ALG_MAX_INT];

	/*
	 * The nonce len for use with AES-CCM
	 * Input as bits 56 - 104, odd byte values only. Additionally, minimum
	 * must conform to parameter set requirements.
	 *
	 * required: only for AES-CCM
	 */
	int noncelen;

	/*
	 * The mac len for use with AES-CCM.
	 * Input as bits mod 8. Minimum must conform to parameter set
	 * requirements.
	 *
	 * required: only for AES-CCM
	 */
	int maclen;

	/*
	 * KDF options (one or more of DEF_ALG_KAS_FFC_CONCATENATION,
	 * DEF_ALG_KAS_FFC_ASN1)
	 * required: always
	 */
	unsigned int kas_ffc_kdfoption;

	/*
	 * Some IUTs require a specific pattern for the OtherInfo portion of the
	 * KDFs for KAS.  An "oiPattern" is specified in the KDF registration to
	 * accommodate such requirements.  Regardless of the oiPattern
	 * specified, the OI bitlength must be 240 for ECC, and 376 for ECC.
	 * The OI will be padded with random bits (or the most significant bits
	 * utilized) when the specified OI pattern does not meet the bitlength
	 * requirement
	 *
	 * Pattern candidates:
	 *
	 * o  literal[123456789ABCDEF]
	 *
	 *   *  uses the specified hex within "[]".  literal[123456789ABCDEF]
	 *      substitutes "123456789ABCDEF" in place of the field
	 *
	 * o  uPartyInfo
	 *
	 *   *  uPartyId { || dkmNonce }
	 *
	 *   +  dkmNonce is provided by party u for static schemes
	 *
	 * o  vPartyInfo
	 *
	 *   *  vPartyId
	 *
	 * o  counter
	 *
	 *   *  32bit counter starting at "1" (0x00000001)
	 *
	 * Example (Note that party U is the server in this case "434156536964",
	 * party V is the IUT "a1b2c3d4e5", using an ECC non-static scheme):
	 *
	 * o  "concatenation" :
	 *    "literal[123456789CAFECAFE]||uPartyInfo||vPartyInfo"
	 *
	 * Evaluated as:
	 *
	 * o  "123456789CAFECAFE434156536964a1b2c3d4e5b16c5f78ef56e8c14a561"
	 *
	 * o  "b16c5f78ef56e8c14a561" are random bits applied to meet length
      	 *    requirements
	 *
	 * required: always
	 */
	char *oipattern;
};

/****************************************************************************
 * KAS FFC data for KDF and key confirmation
 ****************************************************************************/
struct def_algo_kas_ffc_kdfkc {
	/*
	 * Parameter set for the KAS FFC operation
	 *
	 * required: always
	 */
	enum kas_ffc_paramset kas_ffc_paramset;

	/*
	 * One or more ORed cipher definitions covered by the ACVP_HASHMASK
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * One of the following:
	 *
	 * ACVP_CCM
	 * ACVP_AESCMAC
	 * ACVP_HMACSHA2_...
	 *
	 * required: always
	 */
	cipher_t mac;

	/*
	 * Key length supported by the MAC in bits. For AES-based MACs this
	 * value is limited to 128, 192 and 256 bits. For HMAC-based MACs,
	 * this value is allowed to be between 8 and 524288 bits.
	 *
	 * required: always
	 */
	int keylen[DEF_ALG_MAX_INT];

	/*
	 * The nonce len for use with AES-CCM
	 * Input as bits 56 - 104, odd byte values only. Additionally, minimum
	 * must conform to parameter set requirements.
	 *
	 * required: only for AES-CCM
	 */
	int noncelen;

	/*
	 * The mac len for use with AES-CCM.
	 * Input as bits mod 8. Minimum must conform to parameter set
	 * requirements.
	 *
	 * required: only for AES-CCM
	 */
	int maclen;

	/*
	 * KDF options (one or more of DEF_ALG_KAS_FFC_CONCATENATION,
	 * DEF_ALG_KAS_FFC_ASN1)
	 *
	 * required: always
	 */
	unsigned int kas_ffc_kdfoption;

	/*
	 * Some IUTs require a specific pattern for the OtherInfo portion of the
	 * KDFs for KAS.  An "oiPattern" is specified in the KDF registration to
	 * accommodate such requirements.  Regardless of the oiPattern
	 * specified, the OI bitlength must be 240 for ECC, and 376 for ECC.
	 * The OI will be padded with random bits (or the most significant bits
	 * utilized) when the specified OI pattern does not meet the bitlength
	 * requirement
	 *
	 * Pattern candidates:
	 *
	 * o  literal[123456789ABCDEF]
	 *
	 *   *  uses the specified hex within "[]".  literal[123456789ABCDEF]
	 *      substitutes "123456789ABCDEF" in place of the field
	 *
	 * o  uPartyInfo
	 *
	 *   *  uPartyId { || dkmNonce }
	 *
	 *   +  dkmNonce is provided by party u for static schemes
	 *
	 * o  vPartyInfo
	 *
	 *   *  vPartyId
	 *
	 * o  counter
	 *
	 *   *  32bit counter starting at "1" (0x00000001)
	 *
	 * Example (Note that party U is the server in this case "434156536964",
	 * party V is the IUT "a1b2c3d4e5", using an ECC non-static scheme):
	 *
	 * o  "concatenation" :
	 *    "literal[123456789CAFECAFE]||uPartyInfo||vPartyInfo"
	 *
	 * Evaluated as:
	 *
	 * o  "123456789CAFECAFE434156536964a1b2c3d4e5b16c5f78ef56e8c14a561"
	 *
	 * o  "b16c5f78ef56e8c14a561" are random bits applied to meet length
      	 *    requirements
	 *
	 * required: always
	 */
	char *oipattern;

	/*
	 * The role(s) the IUT is to act as for Key Confirmation.
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_FFC_PROVIDER (1 << 0)
#define DEF_ALG_KAS_FFC_RECIPIENT (1 << 1)
	unsigned int kcrole;

	/*
	 * The type(s) the IUT is to act as for Key Conformation.
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_FFC_UNILATERAL (1 << 0)
#define DEF_ALG_KAS_FFC_BILATERAL (1 << 1)
	unsigned int kctype;

	/*
	 * The nonce type(s) the IUT is to use for Key Confirmation.
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_FFC_RANDOM_NONCE (1 << 0)
#define DEF_ALG_KAS_FFC_TIMESTAMP (1 << 1)
#define DEF_ALG_KAS_FFC_SEQUENCE (1 << 2)
#define DEF_ALG_KAS_FFC_TIMESTAMP_SEQUENCE (1 << 3)
	unsigned int noncetype;
};

/****************************************************************************
 * KAS FFC common data
 ****************************************************************************/
struct def_algo_kas_ffc {
	/*
	 * Prerequisites to KAS FFC
	 * required: always
	 * CCM
	 * CMAC
	 * DRBG
	 * DSA or Safeprimes
	 * HMAC
	 * SHA
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
	 * required: always
	 */
#define DEF_ALG_KAS_FFC_DPGEN (1 << 0)
#define DEF_ALG_KAS_FFC_DPVAL (1 << 1)
#define DEF_ALG_KAS_FFC_KEYPAIRGEN (1 << 2)
#define DEF_ALG_KAS_FFC_FULLVAL (1 << 3)
#define DEF_ALG_KAS_FFC_KEYREGEN (1 << 4)
	unsigned int kas_ffc_function;

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
#define DEF_ALG_KAS_FFC_DH_HYBRID_1 (1 << 0)
#define DEF_ALG_KAS_FFC_MQV2 (1 << 1)
#define DEF_ALG_KAS_FFC_DH_EPHEM (1 << 2)
#define DEF_ALG_KAS_FFC_DH_HYBRID_ONE_FLOW (1 << 3)
#define DEF_ALG_KAS_FFC_MQV1 (1 << 4)
#define DEF_ALG_KAS_FFC_DH_ONE_FLOW (1 << 5)
#define DEF_ALG_KAS_FFC_DH_STATIC (1 << 6)
	unsigned int kas_ffc_schema;

	/*
	 * KAS FFC DH role
	 */
#define DEF_ALG_KAS_FFC_INITIATOR (1 << 0)
#define DEF_ALG_KAS_FFC_RESPONDER (1 << 1)
	unsigned int kas_ffc_role;

	/*
	 * KAS FFC Diffie Hellman implementation type:
	 *
	 * * No KDF, no key confirmation
	 * * KDF, no key confirmation
	 * * KDF, key confirmation
	 *
	 * The selected KAS FFC determines the used data structure in the
	 * union type_info
	 */
	enum kas_ffc_dh_type {
		DEF_ALG_KAS_FFC_NO_KDF_NO_KC,
		DEF_ALG_KAS_FFC_KDF_NO_KC,
		DEF_ALG_KAS_FFC_KDF_KC,
	} kas_ffc_dh_type;

	/*
	 * Specific register information for the chosen KAS FFC function type.
	 *
	 * required: always
	 */
	union {
		const struct def_algo_kas_ffc_nokdfnokc *nokdfnokc;
		const struct def_algo_kas_ffc_kdfnokc *kdfnokc;
		const struct def_algo_kas_ffc_kdfkc *kdfkc;
	} type_info;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KAS_FFC_H */
