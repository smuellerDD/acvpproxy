/* leancrypto module definition
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "definition_impl_common.h"

/**************************************************************************
 * AES Definitions
 **************************************************************************/
#define LC_AES_ECB	GENERIC_AES_ECB
#define LC_AES_CBC	GENERIC_AES_CBC
#define LC_AES_CTR	GENERIC_AES_CTR
#define LC_AES_KW	GENERIC_AES_KW

/**************************************************************************
 * Hash Definitions
 **************************************************************************/

/*
 * leancrypto supports LC_SHA, but some target systems are too small memory
 * which do not offer sufficient memory for LDT
 */
#define LC_SHA_NO_LDT(sha_def)						\
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

#define LC_HMAC(x)		GENERIC_HMAC(x)
#define LC_SHAKE(x)		GENERIC_SHAKE(x)


/**************************************************************************
 * XOF definitions
 **************************************************************************/
#define LC_XOF(shake_def)						\
	{								\
	.type = DEF_ALG_TYPE_XOF,					\
	.algo = {							\
		.xof = {						\
			.algorithm = shake_def,				\
			.hex = true,					\
			DEF_ALG_DOMAIN(.messagelength, 16, 65536, 8),	\
			DEF_ALG_DOMAIN(.outlength, 16, 65536, 8),	\
			}						\
		},							\
	}

#define LC_KMAC(kmac_def)						\
	{								\
	.type = DEF_ALG_TYPE_XOF,					\
	.algo = {							\
		.xof = {						\
			.algorithm = kmac_def,				\
			.xof = DEF_ALG_XOF_NOT_PRESENT |		\
			       DEF_ALG_XOF_PRESENT,			\
			.hex = true,					\
			DEF_ALG_DOMAIN(.messagelength, 16, 65536, 8),	\
			DEF_ALG_DOMAIN(.outlength, 16, 65536, 8),	\
			DEF_ALG_DOMAIN(.keylength, 128, 524288, 8),	\
			DEF_ALG_DOMAIN(.maclength, 32, 65536, 8),	\
			}						\
		},							\
	}

/**************************************************************************
 * SP800-108 KDF Definitions
 **************************************************************************/
static const struct def_algo_prereqs lc_kdf_hmac_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

/*
 * KDF supports output lengths which are multiple of bytes - we support
 * any .supported_lengths, except for the Feedback mode which must be at least
 * of the size of the message digest.
 */

#define LC_KDF_HMAC_DEF(kdf_type, ctr_loc)				\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(lc_kdf_hmac_prereqs),			\
		.kdf_108_type = kdf_type,				\
		.macalg = ACVP_HMACSHA2_256 | ACVP_HMACSHA2_512 |	\
			  ACVP_HMACSHA3_224 | ACVP_HMACSHA3_256 |	\
			  ACVP_HMACSHA3_384 | ACVP_HMACSHA3_512,	\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = false				\
		}							\
	}

#define LC_KDF_HMAC							\
	LC_KDF_HMAC_DEF(DEF_ALG_KDF_108_COUNTER,			\
			DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	LC_KDF_HMAC_DEF(DEF_ALG_KDF_108_FEEDBACK,			\
			DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	LC_KDF_HMAC_DEF(DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,	\
			DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA)

/**************************************************************************
 * SP800-132 PBKDF Definitions
 **************************************************************************/
#define LC_PBKDF(x)	GENERIC_PBKDF(x)

/**************************************************************************
 * HKDF Definitions
 **************************************************************************/
#define LC_HKDF								\
	{								\
	.type = DEF_ALG_TYPE_HKDF,					\
	.algo.hkdf = {							\
		DEF_PREREQS(lc_kdf_hmac_prereqs),			\
		.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |	\
				   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,	\
		.fixed_info_pattern_type = {				\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO },\
		.cipher_spec = {					\
			.macalg = ACVP_SHA256 | ACVP_SHA512,		\
			DEF_ALG_DOMAIN(.z, 224, 65336, 8),		\
			.l = 2048,					\
			}						\
		}							\
	}

/**************************************************************************
 * DRBG Definitions
 **************************************************************************/

static const struct def_algo_prereqs hmac_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs sha_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define LC_DRBG_CAPS_SHA512						\
	{								\
	.mode = ACVP_SHA512,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 1024,					\
	}

#define LC_DRBG_HMAC							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED,			\
			.reseed = true,					\
			.capabilities = {				\
				LC_DRBG_CAPS_SHA512 },			\
			.num_caps = 1,					\
			}						\
		}							\
	}

#define LC_DRBG_HASH							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED,			\
			.reseed = true,					\
			.capabilities = {				\
				LC_DRBG_CAPS_SHA512 },			\
			.num_caps = 1,					\
			}						\
		}							\
	}

/**************************************************************************
 * Implementation Definitions
 **************************************************************************/

#define LC_SHA3_ALGOS							\
	LC_SHA_NO_LDT(ACVP_SHA3_224),					\
	LC_SHA_NO_LDT(ACVP_SHA3_256),					\
	LC_SHA_NO_LDT(ACVP_SHA3_384),					\
	LC_SHA_NO_LDT(ACVP_SHA3_512),					\
	LC_SHAKE(ACVP_SHAKE128),					\
	LC_SHAKE(ACVP_SHAKE256),					\
	LC_XOF(ACVP_CSHAKE128),						\
	LC_XOF(ACVP_CSHAKE256),						\
	LC_KMAC(ACVP_KMAC128),						\
	LC_KMAC(ACVP_KMAC256),						\
	LC_PBKDF(ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 | ACVP_SHA3_512)

static const struct def_algo lc_c[] = {
	LC_SHA3_ALGOS,

//	LC_AES_ECB,
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW,

	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA512),

	LC_HMAC(ACVP_HMACSHA2_256),
	LC_HMAC(ACVP_HMACSHA2_512),

	LC_KDF_HMAC,

	LC_PBKDF(ACVP_SHA256 | ACVP_SHA512),

	LC_DRBG_HMAC,
	LC_DRBG_HASH,

	LC_HKDF
};

static const struct def_algo lc_avx2[] = {
	LC_SHA3_ALGOS
};

static const struct def_algo lc_shake_avx2_4x[] = {
	LC_SHAKE(ACVP_SHAKE128),
	LC_SHAKE(ACVP_SHAKE256),
};

static const struct def_algo lc_avx512[] = {
	LC_SHA3_ALGOS
};

static const struct def_algo lc_arm_neon[] = {
	LC_SHA3_ALGOS
};

static const struct def_algo lc_arm_asm[] = {
	LC_SHA3_ALGOS
};

static const struct def_algo lc_arm_ce[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW,

	LC_SHA3_ALGOS
};

static const struct def_algo lc_aesni[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW
};

static const struct def_algo lc_risc64[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map lc_algo_map [] = {
/* C cipher implementation, C block-chaining **********************************/
	{
		SET_IMPLEMENTATION(lc_c),
		.algo_name = "leancrypto",
		.processor = "",
		.impl_name = "C"
	},

/* AVX2 cipher implementation, ************************************************/
	{
		SET_IMPLEMENTATION(lc_avx2),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "AVX2"
	},

/* AVX2 cipher implementation, ************************************************/
	{
		SET_IMPLEMENTATION(lc_shake_avx2_4x),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "AVX2_4X"
	},

/* AVX512 cipher implementation, **********************************************/
	{
		SET_IMPLEMENTATION(lc_avx512),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "AVX512"
	},

/* AESNI cipher implementation, ***********************************************/
	{
		SET_IMPLEMENTATION(lc_aesni),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "AESNI"
	},

/* ARMv7 NEON cipher implementation, ******************************************/
	{
		SET_IMPLEMENTATION(lc_arm_neon),
		.algo_name = "leancrypto",
		.processor = "ARM32",
		.impl_name = "ARM_NEON"
	},

/* ARMv8 ASM cipher implementation, ********************************************/
	{
		SET_IMPLEMENTATION(lc_arm_asm),
		.algo_name = "leancrypto",
		.processor = "ARM64",
		.impl_name = "ARM_ASM"
	},

/* ARMv8 CE cipher implementation, ********************************************/
	{
		SET_IMPLEMENTATION(lc_arm_ce),
		.algo_name = "leancrypto",
		.processor = "ARM64",
		.impl_name = "ARM_CE"
	},

/* RISC-V 64 cipher assembler implementation, *********************************/
	{
		SET_IMPLEMENTATION(lc_risc64),
		.algo_name = "leancrypto",
		.processor = "RISC-V 64",
		.impl_name = "RISCV64"
	},

};

ACVP_DEFINE_CONSTRUCTOR(lc_register)
static void lc_register(void)
{
	acvp_register_algo_map(lc_algo_map,
			       ARRAY_SIZE(lc_algo_map));
}

ACVP_EXTENSION(lc_algo_map)
