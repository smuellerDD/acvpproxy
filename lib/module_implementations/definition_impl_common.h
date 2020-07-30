/* ACVP Proxy common cipher definitions
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_IMP_COMMON_H
#define DEFINITION_IMP_COMMON_H

#ifdef __cplusplus
extern "C"
{
#endif

/**************************************************************************
 * AES Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_gcm_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs generic_ccm_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
};

#define GENERIC_AES_ALGO_GEN(x)						\
	.type = DEF_ALG_TYPE_SYM,					\
	.algo.sym.algorithm = x,					\
	.algo.sym.direction = DEF_ALG_SYM_DIRECTION_ENCRYPTION |	\
			      DEF_ALG_SYM_DIRECTION_DECRYPTION,		\
	.algo.sym.keylen = DEF_ALG_SYM_KEYLEN_128 |			\
			   DEF_ALG_SYM_KEYLEN_192 |			\
			   DEF_ALG_SYM_KEYLEN_256

/**
 * @brief AES CBC definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CBC							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CBC),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES OFB definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_OFB							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_OFB),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES CFB128 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CFB128						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CFB128),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES CFB8 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CFB8						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CFB8),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 8, 65536, 8),			\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES CFB1 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CFB1						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CFB1),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 1, 65536, 1),			\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES ECB definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_ECB							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_ECB),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	}

/**
 * @brief AES CTR definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 *	* external IV generation
 *	* unhandled counter overflow
 *	* counter is incremented
 */
#define GENERIC_AES_CTR							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CTR),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 8, 128, 8),			\
	.algo.sym.ivlen = { 128, },					\
	.algo.sym.ctrsource = DEF_ALG_SYM_CTR_EXTERNAL,			\
	.algo.sym.ctroverflow = DEF_ALG_SYM_CTROVERFLOW_UNHANDLED,	\
	.algo.sym.ctrincrement = DEF_ALG_SYM_CTRINCREMENT_INCREMENT	\
	}

/**
 * @brief AES KeyWrap No-Padding definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_KW							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_KW),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 4096, 128),		\
	.algo.sym.ivlen = { 64, },					\
	.algo.sym.kwcipher = DEF_ALG_SYM_KW_CIPHER,			\
	}

/**
 * @brief AES KeyWrap with Padding definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_KWP							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_KWP),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 8, 4096, 8),			\
	.algo.sym.ivlen = { 64, },					\
	.algo.sym.kwcipher = DEF_ALG_SYM_KW_CIPHER,			\
	}

/**
 * @brief AES XTS definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 *	* tweak key is handled as hexadecimal string
 */
#define GENERIC_AES_XTS							\
	{								\
	.type = DEF_ALG_TYPE_SYM,					\
	.algo.sym.algorithm = ACVP_XTS,					\
	.algo.sym.direction = DEF_ALG_SYM_DIRECTION_ENCRYPTION |	\
			      DEF_ALG_SYM_DIRECTION_DECRYPTION,		\
	.algo.sym.keylen = DEF_ALG_SYM_KEYLEN_128 |			\
			   DEF_ALG_SYM_KEYLEN_256,			\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.tweakformat = DEF_ALG_SYM_XTS_TWEAK_128HEX,		\
	.algo.sym.tweakmode = DEF_ALG_SYM_XTS_TWEAK_HEX,		\
	}

/**
 * @brief AES GMAC definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed tag lengths
 *	* support for zero values AAD
 * 	* arbitrary plaintext length
 *	* external IV generation
 *	* IV generation following section 8.2.1 and 8.2.2. of SP800-38D
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GMAC(x)						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GMAC),				\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_EXTERNAL,			\
	.algo.sym.ivgenmode = x,					\
	.algo.sym.aadlen = { 128, 256, 120, DEF_ALG_ZERO_VALUE },	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}

#define GENERIC_AES_GMAC_821	GENERIC_AES_GMAC(DEF_ALG_SYM_IVGENMODE_821)
#define GENERIC_AES_GMAC_822	GENERIC_AES_GMAC(DEF_ALG_SYM_IVGENMODE_822)

/**
 * @brief AES GCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 * 	* arbitrary plaintext length
 *	* external/internal IV generation - specify with param ivtype
 *	* IV generation following section 8.2.1 / 8.2.2. of SP800-38D -
 *	  specify with param mode
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GCM_NONNULL(mode, ivtype)				\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GCM),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = ivtype,					\
	.algo.sym.ivgenmode = mode,					\
	.algo.sym.aadlen = { 128, 256, 120, DEF_ALG_ZERO_VALUE },	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}

/* External IV */
#define GENERIC_AES_GCM_EIV_NONNULL(mode)				\
		GENERIC_AES_GCM_NONNULL(mode, DEF_ALG_SYM_IVGEN_EXTERNAL)
#define GENERIC_AES_GCM_822_NONNULL					\
		GENERIC_AES_GCM_EIV_NONNULL(DEF_ALG_SYM_IVGENMODE_822)
#define GENERIC_AES_GCM_821_NONNULL					\
		GENERIC_AES_GCM_EIV_NONNULL(DEF_ALG_SYM_IVGENMODE_821)
#define GENERIC_AES_GCM_822						\
		GENERIC_AES_GCM_822_NONNULL, GENERIC_AES_GMAC_822
#define GENERIC_AES_GCM_821						\
		GENERIC_AES_GCM_821_NONNULL, GENERIC_AES_GMAC_821

/* Internal IV */
#define GENERIC_AES_GCM_IIV_NONNULL(mode)				\
		GENERIC_AES_GCM_NONNULL(mode, DEF_ALG_SYM_IVGEN_INTERNAL)
#define GENERIC_AES_GCM_822_IIV_NONNULL					\
		GENERIC_AES_GCM_IIV_NONNULL(DEF_ALG_SYM_IVGENMODE_822)
#define GENERIC_AES_GCM_821_IIV_NONNULL					\
		GENERIC_AES_GCM_IIV_NONNULL(DEF_ALG_SYM_IVGENMODE_821)
#define GENERIC_AES_GCM_822_IIV						\
		GENERIC_AES_GCM_822_NONNULL, GENERIC_AES_GMAC_822
#define GENERIC_AES_GCM_821_IIV						\
		GENERIC_AES_GCM_821_NONNULL, GENERIC_AES_GMAC_821

/**
 * @brief AES CCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed nonce lengths
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CCM							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CCM),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, DEF_ALG_ZERO_VALUE, 256, 8),	\
	.algo.sym.ivlen = { 56, 64, 72, 80, 88, 96, 104, },		\
	.algo.sym.aadlen = { DEF_ALG_ZERO_VALUE, 256, 65536 },		\
	.algo.sym.taglen = { 32, 48, 64, 80, 96, 112, 128 },		\
	.algo.sym.prereqvals = generic_ccm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_ccm_prereqs)	\
	}

/**
 * @brief AES CCMP definition used in WPA2
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 256
 *	* nonce length: 13 bytes (104 bits)
 *	* AAD length: 22 bytes, 28 bytes, 30 bytes (240 bits) which is the
 *		 maximum AAD allowed by the IEEE 802.11 spec
 *	* Tag length: 16 (which is equal to M specified in IEEE 802.11)
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CCMP						\
	{								\
	.type = DEF_ALG_TYPE_SYM,					\
	.algo.sym.algorithm = ACVP_CCM,					\
	.algo.sym.direction = DEF_ALG_SYM_DIRECTION_ENCRYPTION |	\
			      DEF_ALG_SYM_DIRECTION_DECRYPTION,		\
	.algo.sym.keylen = DEF_ALG_SYM_KEYLEN_256,			\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 0, 256, 8),			\
	.algo.sym.ivlen = { 104, },					\
	.algo.sym.aadlen = { 176, 224, 240 },				\
	.algo.sym.taglen = { 128 },					\
	.algo.sym.prereqvals = generic_ccm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_ccm_prereqs)	\
	}

/**************************************************************************
 * TDES Definitions
 **************************************************************************/
#define GENERIC_TDES_GEN(x)						\
	.type = DEF_ALG_TYPE_SYM,					\
	.algo.sym.algorithm = x,					\
	.algo.sym.direction = DEF_ALG_SYM_DIRECTION_ENCRYPTION |	\
			      DEF_ALG_SYM_DIRECTION_DECRYPTION,		\
	.algo.sym.keylen = DEF_ALG_SYM_KEYLEN_168			\

/**
 * @brief Triple-DES CBC definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_CBC						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCBC),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

#define GENERIC_TDES_CBCI						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCBCI),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

/**
 * @brief Triple-DES CFB1 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_CFB1						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFB1),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

#define GENERIC_TDES_CFBP1						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFBP1),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

/**
 * @brief Triple-DES CFB8 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_CFB8						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFB8),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

#define GENERIC_TDES_CFBP8						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFBP8),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

/**
 * @brief Triple-DES CFB64 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_CFB64						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFB64),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

#define GENERIC_TDES_CFBP64						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCFBP64),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

/**
 * @brief Triple-DES ECB definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_ECB						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESECB),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	}

/**
 * @brief Triple-DES OFB definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_OFB						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESOFB),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

#define GENERIC_TDES_OFBI						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESOFBI),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 64, 65536, 64),			\
	.algo.sym.ivlen = { 64, },					\
	}

/**
 * @brief Triple-DES CTR definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 *	* external IV generation
 *	* unhandled counter overflow
 *	* counter is incremented
 */
#define GENERIC_TDES_CTR						\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESCTR),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 8, 64, 8),			\
	.algo.sym.ivlen = { 64, },					\
	.algo.sym.ctrsource = DEF_ALG_SYM_CTR_EXTERNAL,			\
	.algo.sym.ctroverflow = DEF_ALG_SYM_CTROVERFLOW_UNHANDLED,	\
	.algo.sym.ctrincrement = DEF_ALG_SYM_CTRINCREMENT_INCREMENT	\
	}

/**************************************************************************
 * Hash Definitions
 **************************************************************************/

/**
 * @brief SHA hash definition.
 *
 * Cipher definition properties
 * 	* byte-wise processing
 *	* support for zero length messages
 *
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_SHA(sha_def)						\
	{								\
	.type = DEF_ALG_TYPE_SHA,					\
	.algo = {							\
		.sha = {						\
			.algorithm = sha_def,				\
			.inbit = false,					\
			.inempty = true,				\
			DEF_ALG_DOMAIN(.messagelength, DEF_ALG_ZERO_VALUE, 65536, 8),\
			}						\
		},							\
	}

/**
 * @brief SHAKE hash definition.
 *
 * Cipher definition properties
 * 	* byte-wise processing
 *	* byte-wise output
 *	* support for zero length messages
 *
 * @param shake_def SHAKE definition provided with cipher_definitions.h
 */
#define GENERIC_SHAKE(shake_def)					\
	{								\
	.type = DEF_ALG_TYPE_SHAKE,					\
	.algo = {							\
		.shake = {						\
			.algorithm = shake_def,				\
			.inbit = false,					\
			.inempty = true,				\
			.outbit = false,				\
			DEF_ALG_DOMAIN(.outlength, 16, 65536, 8),	\
			}						\
		},							\
	}

/**
 * @brief HMAC definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 * 	* arbitrary key lengths (KS < BS, KS == BS, KS > BS)
 *
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_HMAC(sha_def)						\
	{								\
	.type = DEF_ALG_TYPE_HMAC,					\
	.algo = {							\
		.hmac = {						\
			.algorithm = sha_def,				\
			.prereqvals = {					\
				.algorithm = "SHA",			\
				.valvalue = "same"			\
				},					\
			DEF_ALG_DOMAIN(.keylen, 8, 524288, 8),		\
			}						\
		},							\
	}

/**
 * @brief CMAC AES definition.
 *
 * Cipher definition properties
 *	* dependency on AES is satisfied within the same ACVP register op
 *
 * @param key_length supported AES key lengths provided with
 *		     cipher_definitions.h
 */
#define GENERIC_CMAC_AES(key_length)					\
	{								\
	.type = DEF_ALG_TYPE_CMAC,					\
	.algo = {							\
		.cmac = {						\
			.algorithm = ACVP_CMAC_AES,			\
			.prereqvals = {					\
				.algorithm = "AES",			\
				.valvalue = "same"			\
				},					\
			.direction = DEF_ALG_CMAC_GENERATION |		\
				     DEF_ALG_CMAC_VERIFICATION,		\
			.keylen = key_length,				\
			DEF_ALG_DOMAIN(.msglen, 8, 524288, 8),		\
			}						\
		},							\
	}

/**
 * @brief CMAC TDES definition.
 *
 * Cipher definition properties
 *	* dependency on AES is satisfied within the same ACVP register op
 */
#define GENERIC_CMAC_TDES						\
	{								\
	.type = DEF_ALG_TYPE_CMAC,					\
	.algo = {							\
		.cmac = {						\
			.algorithm = ACVP_CMAC_TDES,			\
			.prereqvals = {					\
				.algorithm = "TDES",			\
				.valvalue = "same"			\
				},					\
			.direction = DEF_ALG_CMAC_GENERATION |		\
				     DEF_ALG_CMAC_VERIFICATION,		\
			.keylen = DEF_ALG_SYM_KEYLEN_168, 		\
			DEF_ALG_DOMAIN(.msglen, 8, 524288, 8),		\
			}						\
		},							\
	}

/**************************************************************************
 * KDF Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_pbkdf_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

/**
 * @brief PBKDF definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 * 	* byte-wise definition of key lengths and salt lengths
 *	* arbitrary iteration count
 *
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_PBKDF(sha_def)						\
	{								\
	.type = DEF_ALG_TYPE_PBKDF,					\
	.algo = {							\
		.pbkdf = {						\
			.hashalg = sha_def,				\
			DEF_PREREQS(generic_pbkdf_prereqs),		\
			DEF_ALG_DOMAIN(.keylen, 128, 4096, 8),		\
			DEF_ALG_DOMAIN(.iteration_count, 10, 1000, 1),	\
			DEF_ALG_DOMAIN(.passwordlen, 8, 128, 1),	\
			DEF_ALG_DOMAIN(.saltlen, 128, 4096, 8),		\
			}						\
		},							\
	}

/**************************************************************************
 * Safeprimes Definitions
 **************************************************************************/

/**
 * @brief DH key generation with safe primes
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *
 * @param mode One definition from enum safeprimes_mode (see
 *	       definition_cipher_safeprimes.h)
 * @param groups One or more combined with an OR
 *		 ACVP_DH_MODP_2048
 *		 ACVP_DH_MODP_3072
 *		 ACVP_DH_MODP_4096
 *		 ACVP_DH_MODP_6144
 *		 ACVP_DH_MODP_8192
 *		 ACVP_DH_FFDHE_2048
 *		 ACVP_DH_FFDHE_3072
 *		 ACVP_DH_FFDHE_4096
 *		 ACVP_DH_FFDHE_6144
 *		 ACVP_DH_FFDHE_8192
 */
#define GENERIC_SAFEPRIMES(mode, groups)				\
	{								\
	.type = DEF_ALG_TYPE_SAFEPRIMES,				\
	.algo.safeprimes = {						\
		.prereqvals = {						\
				.algorithm = "DRBG",			\
				.valvalue = "same"			\
			},						\
		.safeprime_mode = mode,					\
		.safeprime_groups = groups,				\
		},							\
	}

/**************************************************************************
 * KAS ECC Shared Secret Computation Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_ecdh_ssc_r3_prereqs[] = {
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs generic_ecdh_ssc_r3_hash_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct
def_algo_kas_ecc_r3_schema generic_ecc_ssc_r3_ephem_unified[] = { {
	.schema = DEF_ALG_KAS_ECC_R3_EPHEMERAL_UNIFIED,
	.kas_ecc_role = DEF_ALG_KAS_ECC_R3_INITIATOR |
			DEF_ALG_KAS_ECC_R3_RESPONDER,
} };

/**
 * @brief ECC Shared Secret Computation
 *
 * Cipher definition properties
 * 	* initiator and responder
 *	* ephemeral unitified schema
 *	* no hashing of shared secret
 *
 * @param curve One or more ECC curves combined with an OR
 */
#define GENERIC_KAS_ECC_SSC_R3(curve)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC_R3,				\
	.algo.kas_ecc_r3 = {						\
		DEF_PREREQS(generic_ecdh_ssc_r3_prereqs),		\
		.kas_ecc_function = DEF_ALG_KAS_ECC_R3_SSC,		\
		.schema = generic_ecc_ssc_r3_ephem_unified,		\
		.schema_num = ARRAY_SIZE(generic_ecc_ssc_r3_ephem_unified),\
		.domain_parameter = curve,				\
		},							\
	}

/**
 * @brief ECC Shared Secret Computation
 *
 * Cipher definition properties
 * 	* initiator and responder
 *	* ephemeral unitified schema
 *	* hashing of shared secret
 *
 * @param curve One or more ECC curves combined with an OR
 * @param hash One and only one hash definition
 */
#define GENERIC_KAS_ECC_SSC_R3_HASH(curve, hash)			\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC_R3,				\
	.algo.kas_ecc_r3 = {						\
		DEF_PREREQS(generic_ecdh_ssc_r3_hash_prereqs),		\
		.kas_ecc_function = DEF_ALG_KAS_ECC_R3_SSC,		\
		.schema = generic_ecc_ssc_r3_ephem_unified,		\
		.schema_num = ARRAY_SIZE(generic_ecc_ssc_r3_ephem_unified),\
		.domain_parameter = curve,				\
		.hash_z = hash,						\
		},							\
	}


/**************************************************************************
 * KAS FFC Shared Secret Computation Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_dh_ssc_r3_prereqs[] = {
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs generic_dh_ssc_r3_hash_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct
def_algo_kas_ffc_r3_schema generic_ffc_ssc_r3_ephem_unified[] = { {
	.schema = DEF_ALG_KAS_FFC_R3_DH_EPHEM,
	.kas_ffc_role = DEF_ALG_KAS_FFC_R3_INITIATOR |
			DEF_ALG_KAS_FFC_R3_RESPONDER,
} };

/**
 * @brief FFC Shared Secret Computation
 *
 * Cipher definition properties
 * 	* initiator and responder
 *	* ephemeral unitified schema
 *	* no hashing of shared secret
 *
 * @param groups One or more combined with an OR
 *		 ACVP_DH_MODP_2048
 *		 ACVP_DH_MODP_3072
 *		 ACVP_DH_MODP_4096
 *		 ACVP_DH_MODP_6144
 *		 ACVP_DH_MODP_8192
 *		 ACVP_DH_FFDHE_2048
 *		 ACVP_DH_FFDHE_3072
 *		 ACVP_DH_FFDHE_4096
 *		 ACVP_DH_FFDHE_6144
 *		 ACVP_DH_FFDHE_8192
 */
#define GENERIC_KAS_FFC_SSC_R3(groups)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_FFC_R3,				\
	.algo.kas_ffc_r3 = {						\
		DEF_PREREQS(generic_dh_ssc_r3_prereqs),			\
		.kas_ffc_function = DEF_ALG_KAS_FFC_R3_SSC,		\
		.schema = generic_ffc_ssc_r3_ephem_unified,		\
		.schema_num = ARRAY_SIZE(generic_ffc_ssc_r3_ephem_unified),\
		.domain_parameter = groups,				\
		},							\
	}

/**
 * @brief FFC Shared Secret Computation
 *
 * Cipher definition properties
 * 	* initiator and responder
 *	* ephemeral unitified schema
 *	* hashing of shared secret
 *
 * @param groups One or more combined with an OR
 *		 ACVP_DH_MODP_2048
 *		 ACVP_DH_MODP_3072
 *		 ACVP_DH_MODP_4096
 *		 ACVP_DH_MODP_6144
 *		 ACVP_DH_MODP_8192
 *		 ACVP_DH_FFDHE_2048
 *		 ACVP_DH_FFDHE_3072
 *		 ACVP_DH_FFDHE_4096
 *		 ACVP_DH_FFDHE_6144
 *		 ACVP_DH_FFDHE_8192
 * @param hash One and only one hash definition
 */
#define GENERIC_KAS_FFC_SSC_R3_HASH(groups, hash)			\
	{								\
	.type = DEF_ALG_TYPE_KAS_FFC_R3,				\
	.algo.kas_ffc_r3 = {						\
		DEF_PREREQS(generic_dh_ssc_r3_hash_prereqs),		\
		.kas_ffc_function = DEF_ALG_KAS_FFC_R3_SSC,		\
		.schema = generic_ffc_ssc_r3_ephem_unified,		\
		.schema_num = ARRAY_SIZE(generic_ffc_ssc_r3_ephem_unified),\
		.domain_parameter = groups,				\
		.hash_z = hash,						\
		},							\
	}

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_IMP_COMMON_H */
