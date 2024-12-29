/* ACVP Proxy common cipher definitions
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
 * @brief AES CBC-CS1 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CBC_CS1						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CBC_CS1),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 8),			\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES CBC-CS2 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CBC_CS2						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CBC_CS2),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 8),			\
	.algo.sym.ivlen = { 128, },					\
	}

/**
 * @brief AES CBC-CS3 definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 * 	* arbitrary plaintext length
 */
#define GENERIC_AES_CBC_CS3						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CBC_CS3),				\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 8),			\
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
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 8),			\
	.algo.sym.tweakformat = DEF_ALG_SYM_XTS_TWEAK_128HEX,		\
	.algo.sym.tweakmode = DEF_ALG_SYM_XTS_TWEAK_HEX,		\
	.algo.sym.xts_data_unit_len_matches_payload = true		\
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
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GMAC						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GMAC),				\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_EXTERNAL,			\
	DEF_ALG_DOMAIN(.algo.sym.aadlen, DEF_ALG_ZERO_VALUE, 65536, 8),	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}

/* These definitions are deprecated, but retained for backwards compatibility */
#define GENERIC_AES_GMAC_821	GENERIC_AES_GMAC
#define GENERIC_AES_GMAC_822	GENERIC_AES_GMAC

/**
 * @brief AES GCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 *	* arbitrary plaintext length
 *	* external IV generation
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GCM_EIV_NONNULL					\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GCM),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_EXTERNAL,			\
	DEF_ALG_DOMAIN(.algo.sym.aadlen, DEF_ALG_ZERO_VALUE, 65536, 8),	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}

#define GENERIC_AES_GCM							\
	    GENERIC_AES_GCM_EIV_NONNULL, GENERIC_AES_GMAC
/* These definitions are deprecated, but retained for backwards compatibility */
#define GENERIC_AES_GCM_822_NONNULL	GENERIC_AES_GCM_EIV_NONNULL
#define GENERIC_AES_GCM_821_NONNULL	GENERIC_AES_GCM_EIV_NONNULL
#define GENERIC_AES_GCM_822		GENERIC_AES_GCM
#define GENERIC_AES_GCM_821		GENERIC_AES_GCM

/**
 * @brief AES GCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 *	* arbitrary plaintext length
 *	* internal IV generation
 *	* IV generation following section 8.2.1 / 8.2.2. of SP800-38D -
 *	  specify with param mode
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GCM_IIV_NONNULL(mode)				\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GCM),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 65536, 128),		\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_INTERNAL,			\
	.algo.sym.ivgenmode = mode,					\
	DEF_ALG_DOMAIN(.algo.sym.aadlen, DEF_ALG_ZERO_VALUE, 65536, 8),	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}

#define GENERIC_AES_GCM_822_IIV_NONNULL					\
	GENERIC_AES_GCM_IIV_NONNULL(DEF_ALG_SYM_IVGENMODE_822)
#define GENERIC_AES_GCM_821_IIV_NONNULL					\
	GENERIC_AES_GCM_IIV_NONNULL(DEF_ALG_SYM_IVGENMODE_821)
#define GENERIC_AES_GCM_822_IIV						\
	GENERIC_AES_GCM_822_IIV_NONNULL, GENERIC_AES_GMAC_822
#define GENERIC_AES_GCM_821_IIV						\
	GENERIC_AES_GCM_821_IIV_NONNULL, GENERIC_AES_GMAC_821

/**
 * @brief AES CCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed nonce lengths
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 *	* arbitrary plaintext length
 */
#define GENERIC_AES_CCM							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CCM),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, DEF_ALG_ZERO_VALUE, 256, 8),	\
	.algo.sym.ivlen = { 56, 64, 72, 80, 88, 96, 104, },		\
	DEF_ALG_DOMAIN(.algo.sym.aadlen, DEF_ALG_ZERO_VALUE, 524288, 8),\
	.algo.sym.taglen = { 32, 48, 64, 80, 96, 112, 128 },		\
	.algo.sym.prereqvals = generic_ccm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_ccm_prereqs)	\
	}

/**
 * @brief AES CCMP definition used in WPA2.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 256
 *	* nonce length: 13 bytes (104 bits)
 *	* AAD length: 22 bytes, 28 bytes, 30 bytes (240 bits) which is the
 *		 maximum AAD allowed by the IEEE 802.11 spec
 *	* Tag length: 16 (which is equal to M specified in IEEE 802.11)
 *	* arbitrary plaintext length
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

/**
 * @brief Triple-DES KeyWrap No-Padding definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 192
 * 	* arbitrary plaintext length
 */
#define GENERIC_TDES_KW							\
	{								\
	GENERIC_TDES_GEN(ACVP_TDESKW),					\
	DEF_ALG_DOMAIN(.algo.sym.ptlen, 128, 4096, 128),		\
	.algo.sym.ivlen = { 64, },					\
	.algo.sym.kwcipher = DEF_ALG_SYM_KW_CIPHER,			\
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
			DEF_ALG_DOMAIN(.messagelength, DEF_ALG_ZERO_VALUE, 65536, 8),\
			.largetest = { 1, 2, 4, 8 },			\
			}						\
		},							\
	}

#define GENERIC_SHA2_DEF						\
	ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512
#define GENERIC_SHA2_TRUNCATED_DEF					\
	ACVP_SHA512224 | ACVP_SHA512256
#define GENERIC_SHA3_DEF						\
	ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 | ACVP_SHA3_512

/**
 * @brief SHAKE definition.
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
			DEF_ALG_DOMAIN(.messagelength, 16, 65536, 8),	\
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
			DEF_ALG_DOMAIN(.keylen, 112, 524288, 8),	\
			}						\
		},							\
	}

#define GENERIC_HMACSHA2_DEF						\
	ACVP_HMACSHA2_224 | ACVP_HMACSHA2_256 |				\
	ACVP_HMACSHA2_384 | ACVP_HMACSHA2_512
#define GENERIC_HMACSHA2_TRUNCATED_DEF					\
	ACVP_HMACSHA2_512224 | ACVP_HMACSHA2_512256
#define GENERIC_HMACSHA3_DEF						\
	ACVP_HMACSHA3_224 | ACVP_HMACSHA3_256 |				\
	ACVP_HMACSHA3_384 | ACVP_HMACSHA3_512

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
static const struct def_algo_prereqs generic_kbkdf_hmac_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs generic_kbkdf_aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "CMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs generic_kbkdf_tdes_prereqs[] = {
	{
		.algorithm = "TDES",
		.valvalue = "same"
	},
	{
		.algorithm = "CMAC",
		.valvalue = "same"
	},
};

/**
 * @brief KBKDF definition.
 *
 * Cipher definition properties
 *	* derived key length: 112-4096 increment 8
 *	* supports empty iv
 *	* does not require empty iv
 *
 * @param prereqs array of prerequisites
 * @param kdf_type KDF type (counter, feedback, or double pipeline)
 * @param mac_def HMAC or CMAC definition provided with cipher_definitions.h
 * @param ctr_loc counter location
 * @param ctr_lens counter lengths
 */
#define GENERIC_KBKDF(prereqs, kdf_type, mac_def, ctr_loc, ctr_lens)	\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(prereqs),					\
		.kdf_108_type = kdf_type,				\
		.macalg = mac_def,					\
		DEF_ALG_DOMAIN(.supported_lengths, 112, 4096, 8),	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = ctr_lens,				\
		.supports_empty_iv = true,				\
		.requires_empty_iv = false				\
		}							\
	}

/**
 * @brief KBKDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* counter mode
 *	* derived key length: 112-4096 increment 8
 *	* supports empty iv
 *	* does not require empty iv
 *
 * @param prereqs array of prerequisites
 * @param mac_def HMAC or CMAC definition provided with cipher_definitions.h
 * @param ctr_loc counter location
 * @param ctr_lens counter lengths
 */
#define GENERIC_KBKDF_CTR(prereqs, mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF(prereqs, DEF_ALG_KDF_108_COUNTER,			\
		      mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_CTR_HMAC(mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF_CTR(generic_kbkdf_hmac_prereqs,			\
			  mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_CTR_AES(ctr_loc, ctr_lens)			\
	GENERIC_KBKDF_CTR(generic_kbkdf_aes_prereqs,	 		\
			  ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |		\
			  ACVP_CMAC_AES256, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_CTR_TDES(ctr_loc, ctr_lens)			\
	GENERIC_KBKDF_CTR(generic_kbkdf_tdes_prereqs, 			\
			  ACVP_CMAC_TDES, ctr_loc, ctr_lens)

/**
 * @brief KBKDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* feedback mode
 *	* derived key length: 112-4096 increment 8
 *	* supports empty iv
 *	* does not require empty iv
 *
 * @param prereqs array of prerequisites
 * @param mac_def HMAC or CMAC definition provided with cipher_definitions.h
 * @param ctr_loc counter location
 * @param ctr_lens counter lengths
 */
#define GENERIC_KBKDF_FB(prereqs, mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF(prereqs,						\
		      DEF_ALG_KDF_108_FEEDBACK,				\
		      mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_FB_HMAC(mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF_FB(generic_kbkdf_hmac_prereqs, 			\
			 mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_FB_AES(ctr_loc, ctr_lens)				\
	GENERIC_KBKDF_FB(generic_kbkdf_aes_prereqs, 			\
			 ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |		\
			 ACVP_CMAC_AES256, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_FB_TDES(ctr_loc, ctr_lens)			\
	GENERIC_KBKDF_FB(generic_kbkdf_tdes_prereqs, 			\
			 ACVP_CMAC_TDES, ctr_loc, ctr_lens)

/**
 * @brief KBKDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* double pipeline iteration mode
 *	* derived key length: 112-4096 increment 8
 *	* supports empty iv
 *	* does not require empty iv
 *
 * @param prereqs array of prerequisites
 * @param mac_def HMAC or CMAC definition provided with cipher_definitions.h
 * @param ctr_loc counter location
 * @param ctr_lens counter lengths
 */
#define GENERIC_KBKDF_DP(prereqs, mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF(prereqs, DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,\
		      mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_DP_HMAC(mac_def, ctr_loc, ctr_lens)		\
	GENERIC_KBKDF_DP(generic_kbkdf_hmac_prereqs, 			\
			 mac_def, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_DP_AES(ctr_loc, ctr_lens)				\
	GENERIC_KBKDF_DP(generic_kbkdf_aes_prereqs, 			\
			 ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |		\
			 ACVP_CMAC_AES256, ctr_loc, ctr_lens)
#define GENERIC_KBKDF_DP_TDES(ctr_loc, ctr_lens)			\
	GENERIC_KBKDF_DP(generic_kbkdf_tdes_prereqs, 			\
			 ACVP_CMAC_TDES, ctr_loc, ctr_lens)

static const struct def_algo_prereqs generic_kbkdf_kmac_prereqs[] = {
	{
		.algorithm = "KMAC",
		.valvalue = "same"
	},
};

/**
 * @brief KBKDF KMAC definition.
 *
 * Cipher definition properties
 *	* dependency on KMAC is satisfied within the same ACVP register op
 *	* key-derivation-key length: 112-4096 increment 8
 *	* context length: 8-4096 increment 8
 *	* label length: 8-4096 increment 8
 *	* derived key length: 112-4096 increment 8
 *
 * @param kmac_def KMAC definition provided with cipher_definitions.h
 */
#define GENERIC_KBKDF_KMAC(kmac_def)					\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(generic_kbkdf_kmac_prereqs),		\
		.macalg = kmac_def,					\
		.key_derivation_key_length = { 128 },			\
		.context_length = { 128 },				\
		.label_length = { 128 },				\
		.derived_key_length = { 256 },				\
		}							\
	}

static const struct def_algo_prereqs generic_pbkdf_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

/**
 * @brief PBKDF definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *	* byte-wise definition of key lengths and salt lengths
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
			DEF_ALG_DOMAIN(.keylen, 112, 4096, 8),		\
			DEF_ALG_DOMAIN(.iteration_count, 1000, 10000, 1),\
			DEF_ALG_DOMAIN(.passwordlen, 8, 128, 1),	\
			DEF_ALG_DOMAIN(.saltlen, 128, 4096, 8),		\
			}						\
		},							\
	}

static const struct def_algo_prereqs generic_hkdf_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

/**
 * @brief HKDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* default and random salt generation
 *	* shared secret length: 224-2048 increment 8
 *	* derive key length: 2048
 *	* no hybrid shared secret
 *
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_HKDF(mac_def)						\
	{								\
	.type = DEF_ALG_TYPE_HKDF,					\
	.algo.hkdf = {							\
		DEF_PREREQS(generic_hkdf_prereqs),			\
		.hkdf_spec = DEF_ALG_HKDF_SP800_56Crev2,		\
		.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |	\
				   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,	\
		.fixed_info_pattern_type = {				\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO },\
		.cipher_spec = {					\
			.macalg = mac_def,				\
			DEF_ALG_DOMAIN(.z, 224, 8192, 8),		\
			.l = 2048,					\
			.hybrid_shared_secret = false,			\
			}						\
		}							\
	}

static const struct def_algo_prereqs generic_ssh_kdf_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

/**
 * @brief SSH KDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* AES-128, AES-192, and AES-256
 *	* SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
 */
#define GENERIC_SSH_KDF_AES						\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(generic_ssh_kdf_prereqs),			\
		.cipher = ACVP_AES128 | ACVP_AES192 | ACVP_AES256,	\
		.hashalg = ACVP_SHA1 | GENERIC_SHA2_DEF			\
		}							\
	}

/**
 * @brief SSH KDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* Triple-DES
 *	* SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512
 */
#define GENERIC_SSH_KDF_TDES						\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(generic_ssh_kdf_prereqs),			\
		.cipher = ACVP_TDES,					\
		.hashalg = ACVP_SHA1 | GENERIC_SHA2_DEF			\
		}							\
	}

static const struct def_algo_prereqs generic_tls_kdf_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

/**
 * @brief TLS 1.0/1.1 KDF definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 */
#define GENERIC_TLS11_KDF						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(generic_tls_kdf_prereqs),			\
		.tls_version = DEF_ALG_KDF_TLS_1_0_1_1			\
		}							\
	}

/**
 * @brief TLS 1.2 KDF definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *	* SHA-256, SHA-384, and SHA-512
 */
#define GENERIC_TLS12_KDF						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS12,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(generic_tls_kdf_prereqs),			\
		.tls_version = DEF_ALG_KDF_TLS_1_2,			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512	\
		}							\
	}

/**
 * @brief TLS 1.3 KDF definition.
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *	* SHA-384 and SHA-512
 *	* PSK, DHE, and PSK-DHE running modes
 */
#define GENERIC_TLS13_KDF						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS13,					\
	.algo.kdf_tls13 = {						\
		DEF_PREREQS(generic_tls_kdf_prereqs),			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384,			\
		.running_mode = DEF_ALG_KDF_TLS13_MODE_DHE |		\
				DEF_ALG_KDF_TLS13_MODE_PSK |		\
				DEF_ALG_KDF_TLS13_MODE_PSK_DHE		\
		}							\
	}

/**
 * @brief X9.42 KDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* DER type
 *	* derived key length: 112-4096 increment 8
 *	* supplemental info length: 0-256 increment 8
 *	* ZZ length: 8-4096 increment 8
 *
 * @param oids OIDs to test
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_X942_DER_KDF(oids, sha_def)				\
	{								\
	.type = DEF_ALG_TYPE_ANSI_X942,					\
	.algo.ansi_x942 = {						\
		.prereqvals = {						\
			.algorithm = "SHA",				\
			.valvalue = "same"				\
			},						\
		.kdf_type = DEF_ALG_ANSI_X942_KDF_DER,			\
		DEF_ALG_DOMAIN(.key_len, 112, 4096, 8),			\
		DEF_ALG_DOMAIN(.supp_info_len, DEF_ALG_ZERO_VALUE, 256, 8),\
		DEF_ALG_DOMAIN(.zz_len, 8, 4096, 8),			\
		.oid = oids,						\
		.hashalg = sha_def					\
		}							\
	}

#define GENERIC_X942_DER_AES_KDF(sha_def)				\
	GENERIC_X942_DER_KDF(DEF_ALG_ANSI_X942_OID_AES_128_KW |		\
			     DEF_ALG_ANSI_X942_OID_AES_192_KW |		\
			     DEF_ALG_ANSI_X942_OID_AES_256_KW, sha_def)
#define GENERIC_X942_DER_TDES_KDF(sha_def)				\
	GENERIC_X942_DER_KDF(DEF_ALG_ANSI_X942_OID_TDES, sha_def)

/**
 * @brief X9.42 KDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* concatenation type
 *	* derived key length: 112-4096 increment 8
 *	* other info length: 0-256 increment 8
 *	* ZZ length: 8-4096 increment 8
 */
#define GENERIC_X942_CONCATENATION_KDF(sha_def)				\
	{								\
	.type = DEF_ALG_TYPE_ANSI_X942,					\
	.algo.ansi_x942 = {						\
		.prereqvals = {						\
			.algorithm = "SHA",				\
			.valvalue = "same"				\
			},						\
		.kdf_type = DEF_ALG_ANSI_X942_KDF_CONCATENATION,	\
		DEF_ALG_DOMAIN(.key_len, 112, 4096, 8),			\
		DEF_ALG_DOMAIN(.other_info_len, DEF_ALG_ZERO_VALUE, 256, 8),\
		DEF_ALG_DOMAIN(.zz_len, 8, 4096, 8),			\
		.hashalg = sha_def					\
		}							\
	}

/**
 * @brief X9.63 KDF definition.
 *
 * Cipher definition properties
 *	* dependencies are satisfied within the same ACVP register op
 *	* shared info length: 0-1024 increment 8
 *	* field sizes: 224, 233, 256, 283, 384, 409, 521, 571
 *	* derived key length: 128-4096 increment 8
 *
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_X963_KDF(sha_def)					\
	{								\
	.type = DEF_ALG_TYPE_ANSI_X963,					\
	.algo.ansi_x963 = {						\
		.prereqvals = {						\
			.algorithm = "SHA",				\
			.valvalue = "same"				\
			},						\
		.hashalg = sha_def,					\
		DEF_ALG_DOMAIN(.shared_info_len, DEF_ALG_ZERO_VALUE, 1024, 8),\
		.field_size = { 224, 571 },				\
		DEF_ALG_DOMAIN(.key_data_len, 128, 4096, 8)		\
		}							\
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
 *	* ephemeral unified model scheme
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
 *	* initiator and responder
 *	* ephemeral unified model scheme
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
 *	* initiator and responder
 *	* dhEphem scheme
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
 *	* dhEphem scheme
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

/**************************************************************************
 * RSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_rsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_rsa_keygen_gen generic_rsa_keygen_gen_standard = {
	.infogeneratedbyserver = true,
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_STANDARD,
};

static const struct def_algo_rsa_keygen_gen generic_rsa_keygen_gen_crt = {
	.infogeneratedbyserver = true,
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_CRT,
};

/**
 * @brief RSA Key Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_RSA_186_5 or DEF_ALG_RSA_186_4)
 * @param gen_info_keygen Pointer to def_algo_rsa_keygen_gen struct
 * @param specs Array of def_algo_rsa_keygen structs
 * @param specs_num Number of def_algo_rsa_keygen structs in specs array
 */
#define GENERIC_RSA_KEYGEN(rev, gen_info_keygen, specs, specs_num)	\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = rev,				\
			.rsa_mode = DEF_ALG_RSA_MODE_KEYGEN,		\
			DEF_PREREQS(generic_rsa_prereqs),		\
			.gen_info.keygen = gen_info_keygen,		\
			.algspecs.keygen = specs,			\
			.algspecs_num = specs_num,			\
			}						\
		}							\
	}

/**
 * @brief RSA Key Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *	* public exponent format is random
 *	* key format is standard
 *
 * @param rev Revision to use (DEF_ALG_RSA_186_5 or DEF_ALG_RSA_186_4)
 * @param specs Array of def_algo_rsa_keygen structs
 * @param specs_num Number of def_algo_rsa_keygen structs in specs array
 */
#define GENERIC_RSA_KEYGEN_STANDARD(rev, specs, specs_num)		\
	GENERIC_RSA_KEYGEN(rev, &generic_rsa_keygen_gen_standard, specs, specs_num)

/**
 * @brief RSA Key Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *	* public exponent format is random
 *	* key format is CRT
 *
 * @param rev Revision to use (DEF_ALG_RSA_186_5 or DEF_ALG_RSA_186_4)
 * @param specs Array of def_algo_rsa_keygen structs
 * @param specs_num Number of def_algo_rsa_keygen structs in specs array
 */
#define GENERIC_RSA_KEYGEN_CRT(rev, specs, specs_num)			\
	GENERIC_RSA_KEYGEN(rev, &generic_rsa_keygen_gen_crt, specs, specs_num)

/**
 * @brief RSA Signature Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_RSA_186_5 or DEF_ALG_RSA_186_4)
 * @param specs Array of def_algo_rsa_siggen structs
 * @param specs_num Number of def_algo_rsa_siggen structs in specs array
 */
#define GENERIC_RSA_SIGGEN(rev, specs, specs_num)			\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = rev,				\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGGEN,		\
			DEF_PREREQS(generic_rsa_prereqs),		\
			.algspecs.siggen = specs,			\
			.algspecs_num = specs_num,			\
			}						\
		}							\
	}

static const struct def_algo_rsa_sigver_gen generic_rsa_sigver_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
};

/**
 * @brief RSA Signature Verification
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *	* public exponent format is random
 *
 * @param rev Revision to use (DEF_ALG_RSA_186_5 or DEF_ALG_RSA_186_4)
 * @param specs Array of def_algo_rsa_sigver structs
 * @param specs_num Number of def_algo_rsa_sigver structs in specs array
 */
#define GENERIC_RSA_SIGVER(rev, specs, specs_num)			\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = rev,				\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGVER,		\
			DEF_PREREQS(generic_rsa_prereqs),		\
			.gen_info.sigver = &generic_rsa_sigver_gen,	\
			.algspecs.sigver = specs,			\
			.algspecs_num = specs_num,			\
			}						\
		}							\
	}

/**
 * @brief RSA Legacy Signature Verification (FIPS 186-2)
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *	* public exponent format is random
 *
 * @param specs Array of def_algo_rsa_sigver structs
 * @param specs_num Number of def_algo_rsa_sigver structs in specs array
 */
#define GENERIC_RSA_LEGACY_SIGVER(specs, specs_num)			\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = DEF_ALG_RSA_186_4,			\
			.rsa_mode = DEF_ALG_RSA_MODE_LEGACY_SIGVER,	\
			DEF_PREREQS(generic_rsa_prereqs),		\
			.gen_info.sigver = &generic_rsa_sigver_gen,	\
			.algspecs.sigver = specs,			\
			.algspecs_num = specs_num,			\
			}						\
		}							\
	}

/**************************************************************************
 * ECDSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_ecdsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

/**
 * @brief ECDSA Key Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_ECDSA_186_5 or DEF_ALG_ECDSA_186_4)
 * @param curves One or more ECC curves combined with an OR
 * @param mode The secretgenerationmode to use (see definition_cipher_ecdsa.h)
 */
#define GENERIC_ECDSA_KEYGEN(rev, curves, mode)				\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.revision = rev,				\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYGEN,	\
			DEF_PREREQS(generic_ecdsa_prereqs),		\
			.curve = curves,				\
			.secretgenerationmode = mode			\
			}						\
		}							\
	}

/**
 * @brief ECDSA Key Verification
 *
 * Cipher definition properties
 *	* dependency on DRBG is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_ECDSA_186_5 or DEF_ALG_ECDSA_186_4)
 * @param curves One or more ECC curves combined with an OR
 */
#define GENERIC_ECDSA_KEYVER(rev, curves)				\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.revision = rev,				\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYVER,	\
			DEF_PREREQS(generic_ecdsa_prereqs),		\
			.curve = curves					\
			}						\
		}							\
	}

/**
 * @brief ECDSA Signature Generation
 *
 * Cipher definition properties
 *	* dependency on DRBG/SHA is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_ECDSA_186_5 or DEF_ALG_ECDSA_186_4)
 * @param curves One or more ECC curves combined with an OR
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_ECDSA_SIGGEN(rev, curves, sha_def, component)		\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.revision = rev,				\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGGEN,	\
			DEF_PREREQS(generic_ecdsa_prereqs),		\
			.curve = curves,				\
			.hashalg = sha_def,				\
			.component_test = component			\
			}						\
		}							\
	}

/**
 * @brief ECDSA Signature Verification
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *
 * @param rev Revision to use (DEF_ALG_ECDSA_186_5 or DEF_ALG_ECDSA_186_4)
 * @param curves One or more ECC curves combined with an OR
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_ECDSA_SIGVER(rev, curves, sha_def, component)		\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.revision = rev,				\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGVER,	\
			DEF_PREREQS(generic_ecdsa_prereqs),		\
			.curve = curves,				\
			.hashalg = sha_def,				\
			.component_test = component			\
			}						\
		}							\
	}

/**
 * @brief ECDSA Deterministic Signature Generation
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *
 * @param curves One or more ECC curves combined with an OR
 * @param sha_def SHA definition provided with cipher_definitions.h
 */
#define GENERIC_ECDSA_DETSIGGEN(curves, sha_def, component)		\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.revision = DEF_ALG_ECDSA_186_5,		\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_DETERMINISTIC_SIGGEN,\
			DEF_PREREQS(generic_ecdsa_prereqs),		\
			.curve = curves,				\
			.hashalg = sha_def,				\
			.component_test = component			\
			}						\
		}							\
	}

/**************************************************************************
 * EdDSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs generic_eddsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

/**
 * @brief EdDSA Key Generation
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *
 * @param curves One or more EdDSA curves combined with an OR
 */
#define GENERIC_EDDSA_KEYGEN(curves)					\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_KEYGEN,	\
			DEF_PREREQS(generic_eddsa_prereqs),		\
			.curve = curves,				\
			}						\
		}							\
	}

/**
 * @brief EdDSA Signature Generation
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *	* maximum context length of 255 octets
 *
 * @param curves One or more EdDSA curves combined with an OR
 * @param pure If the IUT supports normal 'pure' sigGen functionality
 * @param prehash If the IUT supports accepting a preHashed message to sign
 */
#define GENERIC_EDDSA_SIGGEN(curves, pure, prehash)			\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGGEN,	\
			DEF_PREREQS(generic_eddsa_prereqs),		\
			.curve = curves,				\
			.eddsa_pure = pure,				\
			.eddsa_prehash = prehash,			\
			DEF_ALG_DOMAIN(.context_length, 0, 255, 1)	\
			}						\
		}							\
	}

/**
 * @brief EdDSA Signature Verification
 *
 * Cipher definition properties
 *	* dependency on SHA is satisfied within the same ACVP register op
 *
 * @param curves One or more EdDSA curves combined with an OR
 * @param pure If the IUT supports normal 'pure' sigGen functionality
 * @param prehash If the IUT supports accepting a preHashed message to sign
 */
#define GENERIC_EDDSA_SIGVER(curves, pure, prehash)			\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGVER,	\
			DEF_PREREQS(generic_eddsa_prereqs),		\
			.curve = curves,				\
			.eddsa_pure = pure,				\
			.eddsa_prehash = prehash,			\
			}						\
		}							\
	}

/**
 * @brief ML-DSA Key Generation
 *
 * @param param_set One or more ML-DSA parameter sets combined with an OR
 */
#define GENERIC_ML_DSA_KEYGEN(parm_set)					\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_KEYGEN,	\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

/**
 * @brief ML-DSA Signature Generation
 *
 *  * Cipher definition properties
 *	* message length 8 - 65536 bits
 *
 * @param param_set One or more ML-DSA parameter sets combined with an OR
 * @param determ Specification of deterministic and/or nondeterministic
 *		 operation combined with an OR
 */
#define GENERIC_ML_DSA_SIGGEN(parm_set, determ)				\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGGEN,	\
			.parameter_set = parm_set,			\
			.deterministic = determ,			\
			DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),	\
			}						\
		}							\
	}

/**
 * @brief ML-DSA Signature Verification
 *
 * @param param_set One or more ML-DSA parameter sets combined with an OR
 */
#define GENERIC_ML_DSA_SIGVER(parm_set)					\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGVER,	\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

/**
 * @brief ML-KEM Key Generation
 *
 * @param param_set One or more ML-KEM parameter sets combined with an OR
 */
#define GENERIC_ML_KEM_KEYGEN(parm_set)					\
	{								\
	.type = DEF_ALG_TYPE_ML_KEM,					\
	.algo = {							\
		.ml_kem = {						\
			.ml_kem_mode = DEF_ALG_ML_KEM_MODE_KEYGEN,	\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

/**
 * @brief ML-KEM Encapsulation
 *
 * @param param_set One or more ML-KEM parameter sets combined with an OR
 */
#define GENERIC_ML_KEM_ENCAPSULATION(parm_set)				\
	{								\
	.type = DEF_ALG_TYPE_ML_KEM,					\
	.algo = {							\
		.ml_kem = {						\
			.ml_kem_mode = DEF_ALG_ML_KEM_MODE_ENCAPSULATION,\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

/**
 * @brief ML-KEM Decapsulation
 *
 * @param param_set One or more ML-KEM parameter sets combined with an OR
 */
#define GENERIC_ML_KEM_DECAPSULATION(parm_set)				\
	{								\
	.type = DEF_ALG_TYPE_ML_KEM,					\
	.algo = {							\
		.ml_kem = {						\
			.ml_kem_mode = DEF_ALG_ML_KEM_MODE_DECAPSULATION,\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

/**
 * @brief ML-KEM Encapsulation and Decapsulation
 *
 * @param param_set One or more ML-KEM parameter sets combined with an OR
 */
#define GENERIC_ML_KEM_ENCAPDECAP(parm_set)				\
	{								\
	.type = DEF_ALG_TYPE_ML_KEM,					\
	.algo = {							\
		.ml_kem = {						\
			.ml_kem_mode = DEF_ALG_ML_KEM_MODE_ENCAPSULATION |\
				       DEF_ALG_ML_KEM_MODE_DECAPSULATION,\
			.parameter_set = parm_set,			\
			}						\
		}							\
	}

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_IMP_COMMON_H */
