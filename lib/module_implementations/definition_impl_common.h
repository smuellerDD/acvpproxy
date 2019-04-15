/* ACVP Proxy common cipher definitions
 *
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 128, },					\
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
	.algo.sym.ptlen = { 128, 256, 512, 1024, },			\
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
	.algo.sym.ptlen = { 8, 72, 32, 96, 888, },			\
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
	.algo.sym.ptlen = { 128, 256 },					\
	.algo.sym.tweakformat = DEF_ALG_SYM_XTS_TWEAK_128HEX,		\
	.algo.sym.tweakmode = DEF_ALG_SYM_XTS_TWEAK_HEX,		\
	}

/**
 * @brief AES GCM definition.
 *
 * Cipher definition properties
 *	* encryption / decryption
 *	* key sizes: 128, 192, 256
 *	* all allowed tag lengths
 *	* support for zero values of plaintext and AAD
 * 	* arbitrary plaintext length
 *	* external IV generation
 *	* IV generation following section 8.2.2. of SP800-38D
 *	* AES cipher prerequisites are covered in the same ACVP request
 */
#define GENERIC_AES_GCM_822						\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GCM),					\
	.algo.sym.ptlen = { DEF_ALG_ZERO_VALUE, 128, 256, 120, 248 },	\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_EXTERNAL,			\
	.algo.sym.ivgenmode = DEF_ALG_SYM_IVGENMODE_822,		\
	.algo.sym.aadlen = { 128, 256, 120, DEF_ALG_ZERO_VALUE },	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = generic_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_gcm_prereqs)	\
	}


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
	.algo.sym.ptlen = { DEF_ALG_ZERO_VALUE, 256 },			\
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
	.algo.sym.ptlen = { 128, 256, 384, 512 },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, 128, 256, 512, },			\
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
	.algo.sym.ptlen = { 64, },					\
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
			DEF_ALG_DOMAIN(.messagelength, DEF_ALG_ZERO_VALUE, 65536, 8),						\
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
			.keylen = { 8, 16, 64, 128, 1024 },		\
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
			.msglen = { 128, 256, 136, 264, 524288 }	\
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
			.msglen = { 64, 128, 72, 136, 524288 }		\
			}						\
		},							\
	}

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_IMP_COMMON_H */
