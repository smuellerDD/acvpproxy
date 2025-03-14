/* OpenSSL module definition
 *
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

#include "definition.h"
#include "definition_impl_common.h"

/**************************************************************************
 * AES Definitions
 **************************************************************************/
#define OPENSSL_AES_ECB		GENERIC_AES_ECB
#define OPENSSL_AES_CBC		GENERIC_AES_CBC
#define OPENSSL_AES_CBC_CS1	GENERIC_AES_CBC_CS1
#define OPENSSL_AES_CBC_CS2	GENERIC_AES_CBC_CS2
#define OPENSSL_AES_CBC_CS3	GENERIC_AES_CBC_CS3
#define OPENSSL_AES_CTR		GENERIC_AES_CTR
#define OPENSSL_AES_KW		GENERIC_AES_KW
#define OPENSSL_AES_KWP		GENERIC_AES_KWP
#define OPENSSL_AES_XTS		GENERIC_AES_XTS
#define OPENSSL_AES_OFB		GENERIC_AES_OFB
#define OPENSSL_AES_CFB1	GENERIC_AES_CFB1
#define OPENSSL_AES_CFB8	GENERIC_AES_CFB8
#define OPENSSL_AES_CFB128	GENERIC_AES_CFB128
#define OPENSSL_AES_GCM		GENERIC_AES_GCM
#define OPENSSL_AES_GCM_IIV						\
	GENERIC_AES_GCM_821_IIV_NONNULL, GENERIC_AES_GCM_822_IIV_NONNULL
#define OPENSSL_AES_CCM		GENERIC_AES_CCM

/**************************************************************************
 * TDES Definitions
 **************************************************************************/
#define OPENSSL_TDES_ECB	GENERIC_TDES_ECB
#define OPENSSL_TDES_CBC	GENERIC_TDES_CBC
#define OPENSSL_TDES_OFB	GENERIC_TDES_OFB
#define OPENSSL_TDES_CFB1	GENERIC_TDES_CFB1
#define OPENSSL_TDES_CFB8	GENERIC_TDES_CFB8
#define OPENSSL_TDES_CFB64	GENERIC_TDES_CFB64

/**************************************************************************
 * Hash Definitions
 **************************************************************************/
#define OPENSSL_SHA(x)		GENERIC_SHA(x)
#define OPENSSL_SHAKE(x)	GENERIC_SHAKE(x)
#define OPENSSL_HMAC(x)		GENERIC_HMAC(x)
#define OPENSSL_CMAC_AES						\
	GENERIC_CMAC_GEN_AES((DEF_ALG_SYM_KEYLEN_128 | DEF_ALG_SYM_KEYLEN_192 |\
			     DEF_ALG_SYM_KEYLEN_256))

#define OPENSSL_CMAC_TDES	GENERIC_CMAC_GEN_TDES

/**************************************************************************
 * DRBG Definitions
 **************************************************************************/
static const struct def_algo_prereqs aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
};

#define OPENSSL_DRBG_CAPS_AES128_DF					\
	{								\
	.mode = ACVP_AES128,						\
	.df = true,							\
	.entropyinputlen = { 128 },					\
	.noncelen = { 64 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_AES128_NODF					\
	{								\
	.mode = ACVP_AES128,						\
	.df = false,							\
	.entropyinputlen = { 256 },					\
	.noncelen = { DEF_ALG_ZERO_VALUE },				\
	.persostringlen = { 256 },					\
	.additionalinputlen = { 256 },					\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_AES192_DF					\
	{								\
	.mode = ACVP_AES192,						\
	.df = true,							\
	.entropyinputlen = { 192 },					\
	.noncelen = { 96 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_AES192_NODF					\
	{								\
	.mode = ACVP_AES192,						\
	.df = false,							\
	.entropyinputlen = { 320 },					\
	.noncelen = { DEF_ALG_ZERO_VALUE },				\
	.persostringlen = { 320 },					\
	.additionalinputlen = { 320 },					\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_AES256_DF					\
	{								\
	.mode = ACVP_AES256,						\
	.df = true,							\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_AES256_NODF					\
	{								\
	.mode = ACVP_AES256,						\
	.df = false,							\
	.entropyinputlen = { 384 },					\
	.noncelen = { DEF_ALG_ZERO_VALUE },				\
	.persostringlen = { 384 },					\
	.additionalinputlen = { 384 },					\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CTR(supports_reseed)				\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "ctrDRBG",				\
			DEF_PREREQS(aes_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = supports_reseed,			\
			.capabilities = {				\
				OPENSSL_DRBG_CAPS_AES128_DF,		\
				OPENSSL_DRBG_CAPS_AES128_NODF,		\
				OPENSSL_DRBG_CAPS_AES192_DF,		\
				OPENSSL_DRBG_CAPS_AES192_NODF,		\
				OPENSSL_DRBG_CAPS_AES256_DF,		\
				OPENSSL_DRBG_CAPS_AES256_NODF },	\
			.num_caps = 6,					\
			}						\
		}							\
	}

static const struct def_algo_prereqs drbg_hmac_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs drbg_sha_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define OPENSSL_DRBG_CAPS_SHA1						\
	{								\
	.mode = ACVP_SHA1,						\
	.entropyinputlen = { 128 },					\
	.noncelen = { 64 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 160,						\
	}

#define OPENSSL_DRBG_CAPS_SHA224					\
	{								\
	.mode = ACVP_SHA224,						\
	.entropyinputlen = { 192 },					\
	.noncelen = { 96 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 224,						\
	}

#define OPENSSL_DRBG_CAPS_SHA256					\
	{								\
	.mode = ACVP_SHA256,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_SHA384					\
	{								\
	.mode = ACVP_SHA384,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 384,						\
	}

#define OPENSSL_DRBG_CAPS_SHA512					\
	{								\
	.mode = ACVP_SHA512,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 512,						\
	}

#define OPENSSL_DRBG_CAPS_SHA512224					\
	{								\
	.mode = ACVP_SHA512224,						\
	.entropyinputlen = { 192 },					\
	.noncelen = { 96 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 224,						\
	}

#define OPENSSL_DRBG_CAPS_SHA512256					\
	{								\
	.mode = ACVP_SHA512256,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_SHA3_224					\
	{								\
	.mode = ACVP_SHA3_224,						\
	.entropyinputlen = { 192 },					\
	.noncelen = { 96 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 224,						\
	}

#define OPENSSL_DRBG_CAPS_SHA3_256					\
	{								\
	.mode = ACVP_SHA3_256,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 256,						\
	}

#define OPENSSL_DRBG_CAPS_SHA3_384					\
	{								\
	.mode = ACVP_SHA3_384,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 384,						\
	}

#define OPENSSL_DRBG_CAPS_SHA3_512					\
	{								\
	.mode = ACVP_SHA3_512,						\
	.entropyinputlen = { 256 },					\
	.noncelen = { 128 },						\
	DEF_ALG_DOMAIN(.persostringlen, 0, 512, 128),			\
	DEF_ALG_DOMAIN(.additionalinputlen, 0, 512, 128),		\
	.returnedbitslen = 512,						\
	}

#define OPENSSL_DRBG_HMAC(supports_reseed)				\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(drbg_hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = supports_reseed,			\
			.capabilities = {				\
				OPENSSL_DRBG_CAPS_SHA1,			\
				OPENSSL_DRBG_CAPS_SHA224,		\
				OPENSSL_DRBG_CAPS_SHA256,		\
				OPENSSL_DRBG_CAPS_SHA384,		\
				OPENSSL_DRBG_CAPS_SHA512 },		\
			.num_caps = 5,					\
			}						\
		}							\
	}

#define OPENSSL_DRBG_HASH(supports_reseed)				\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(drbg_sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = supports_reseed,			\
			.capabilities = {				\
				OPENSSL_DRBG_CAPS_SHA1,			\
				OPENSSL_DRBG_CAPS_SHA224,		\
				OPENSSL_DRBG_CAPS_SHA256,		\
				OPENSSL_DRBG_CAPS_SHA384,		\
				OPENSSL_DRBG_CAPS_SHA512 },		\
			.num_caps = 5,					\
			}						\
		}							\
	}

#define OPENSSL_3_DRBG_HMAC						\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(drbg_hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = true,					\
			.capabilities = {				\
				OPENSSL_DRBG_CAPS_SHA1,			\
				OPENSSL_DRBG_CAPS_SHA224,		\
				OPENSSL_DRBG_CAPS_SHA256,		\
				OPENSSL_DRBG_CAPS_SHA384,		\
				OPENSSL_DRBG_CAPS_SHA512,		\
				OPENSSL_DRBG_CAPS_SHA512224,		\
				OPENSSL_DRBG_CAPS_SHA512256,		\
				OPENSSL_DRBG_CAPS_SHA3_224,		\
				OPENSSL_DRBG_CAPS_SHA3_256,		\
				OPENSSL_DRBG_CAPS_SHA3_384,		\
				OPENSSL_DRBG_CAPS_SHA3_512 },		\
			.num_caps = 11,					\
			}						\
		}							\
	}

#define OPENSSL_3_DRBG_HASH						\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(drbg_sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = true,					\
			.capabilities = {				\
				OPENSSL_DRBG_CAPS_SHA1,			\
				OPENSSL_DRBG_CAPS_SHA224,		\
				OPENSSL_DRBG_CAPS_SHA256,		\
				OPENSSL_DRBG_CAPS_SHA384,		\
				OPENSSL_DRBG_CAPS_SHA512,		\
				OPENSSL_DRBG_CAPS_SHA512224,		\
				OPENSSL_DRBG_CAPS_SHA512256,		\
				OPENSSL_DRBG_CAPS_SHA3_224,		\
				OPENSSL_DRBG_CAPS_SHA3_256,		\
				OPENSSL_DRBG_CAPS_SHA3_384,		\
				OPENSSL_DRBG_CAPS_SHA3_512 },		\
			.num_caps = 11,					\
			}						\
		}							\
	}

/**************************************************************************
 * RSA Definitions
 **************************************************************************/

static const struct def_algo_prereqs openssl_rsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_rsa_keygen_caps openssl_rsa_keygen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POWSECSTR
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POWSECSTR
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POWSECSTR
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_6144,
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POWSECSTR
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_8192,
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POWSECSTR
} };

static const struct def_algo_rsa_keygen openssl_rsa_keygen = {
	.rsa_randpq = DEF_ALG_RSA_PQ_PROBABLE_PRIMES,
	.capabilities = openssl_rsa_keygen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_keygen_caps),
};

static const struct def_algo_rsa_keygen openssl_3_rsa_keygen = {
	.rsa_randpq = DEF_ALG_RSA_PQ_PROBABLE_WITH_PROBABLE_AUX_PRIMES,
	.capabilities = openssl_rsa_keygen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_keygen_caps),
};

#define OPENSSL_RSA_KEYGEN						\
	GENERIC_RSA_KEYGEN_STANDARD(DEF_ALG_RSA_186_5, &openssl_rsa_keygen, 1)

#define OPENSSL_3_RSA_KEYGEN						\
	GENERIC_RSA_KEYGEN_STANDARD(DEF_ALG_RSA_186_5, &openssl_3_rsa_keygen, 1)

#define OPENSSL_RSA_186_5_COMMON					\
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1,			\
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512

static const struct def_algo_rsa_siggen_caps openssl_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_186_5_COMMON
} };

static const struct def_algo_rsa_siggen openssl_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps),
} };

#define OPENSSL_RSA_SIGGEN						\
	GENERIC_RSA_SIGGEN(DEF_ALG_RSA_186_5, openssl_rsa_siggen,	\
			   ARRAY_SIZE(openssl_rsa_siggen))

#define OPENSSL_3_RSA_186_5_COMMON					\
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1,			\
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512 |\
		   ACVP_SHA512224 | ACVP_SHA512256

static const struct def_algo_rsa_siggen_caps openssl_3_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_3_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_3_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_3_RSA_186_5_COMMON
} };

static const struct def_algo_rsa_siggen openssl_3_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_3_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_siggen_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_3_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_siggen_caps),
} };

#define OPENSSL_3_RSA_SIGGEN						\
	GENERIC_RSA_SIGGEN(DEF_ALG_RSA_186_5, openssl_3_rsa_siggen,	\
			   ARRAY_SIZE(openssl_3_rsa_siggen))

#define OPENSSL_RSA_SHA3_COMMON						\
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1,			\
	.hashalg = ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 | ACVP_SHA3_512

static const struct def_algo_rsa_siggen_caps openssl_rsa_sha3_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SHA3_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SHA3_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SHA3_COMMON
} };

static const struct def_algo_rsa_siggen openssl_rsa_sha3_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sha3_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha3_siggen_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sha3_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha3_siggen_caps),
} };

#define OPENSSL_RSA_SHA3_SIGGEN						\
	GENERIC_RSA_SIGGEN(DEF_ALG_RSA_186_5, openssl_rsa_sha3_siggen,	\
			   ARRAY_SIZE(openssl_rsa_sha3_siggen))

static const struct def_algo_rsa_sigver_caps openssl_rsa_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_186_5_COMMON
} };

static const struct def_algo_rsa_sigver openssl_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps),
} };

#define OPENSSL_RSA_SIGVER						\
	GENERIC_RSA_SIGVER(DEF_ALG_RSA_186_5, openssl_rsa_sigver,	\
			   ARRAY_SIZE(openssl_rsa_sigver))

static const struct def_algo_rsa_sigver_caps openssl_3_rsa_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_3_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_3_RSA_186_5_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_3_RSA_186_5_COMMON
} };

static const struct def_algo_rsa_sigver openssl_3_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_3_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_3_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_sigver_caps),
} };

#define OPENSSL_3_RSA_SIGVER						\
	GENERIC_RSA_SIGVER(DEF_ALG_RSA_186_5, openssl_3_rsa_sigver,	\
			   ARRAY_SIZE(openssl_3_rsa_sigver))

static const struct def_algo_rsa_sigver_caps openssl_rsa_sha3_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SHA3_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SHA3_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_SHA3_COMMON
} };

static const struct def_algo_rsa_sigver openssl_rsa_sha3_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sha3_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha3_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sha3_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha3_sigver_caps),
} };

#define OPENSSL_RSA_SHA3_SIGVER						\
	GENERIC_RSA_SIGVER(DEF_ALG_RSA_186_5, openssl_rsa_sha3_sigver,	\
			   ARRAY_SIZE(openssl_rsa_sha3_sigver))

// ACVP revision "FIPS 186-5" removed X.93 padding, SHA-1, and 1024-bit moduli, so they need to be tested separately using "FIPS 186-4".

static const struct def_algo_rsa_sigver_caps openssl_rsa_x931_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
} };

static const struct def_algo_rsa_sigver_caps openssl_rsa_sha1_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	.hashalg = ACVP_SHA1,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.hashalg = ACVP_SHA1,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.hashalg = ACVP_SHA1,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.hashalg = ACVP_SHA1,
} };

static const struct def_algo_rsa_sigver_caps openssl_rsa_1024_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
} };

static const struct def_algo_rsa_sigver openssl_rsa_186_4_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_ANSIX931,
	.capabilities = openssl_rsa_x931_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_x931_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sha1_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha1_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sha1_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha1_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_1024_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_1024_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_1024_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_1024_sigver_caps),
} };

#define OPENSSL_RSA_186_4_SIGVER					\
	GENERIC_RSA_SIGVER(DEF_ALG_RSA_186_4, openssl_rsa_186_4_sigver,	\
			   ARRAY_SIZE(openssl_rsa_186_4_sigver))

static const struct def_algo_rsa_sigver_caps openssl_3_rsa_1024_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512 |
		   ACVP_SHA512224 | ACVP_SHA512256
} };

static const struct def_algo_rsa_sigver openssl_3_rsa_186_4_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_ANSIX931,
	.capabilities = openssl_rsa_x931_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_x931_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sha1_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha1_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sha1_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sha1_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_3_rsa_1024_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_1024_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_3_rsa_1024_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_3_rsa_1024_sigver_caps),
} };

#define OPENSSL_3_RSA_186_4_SIGVER					\
	GENERIC_RSA_SIGVER(DEF_ALG_RSA_186_4, openssl_3_rsa_186_4_sigver,\
			   ARRAY_SIZE(openssl_3_rsa_186_4_sigver))

// ACVP revision "FIPS 186-4" removed 1536-bit moduli, so they need to be tested separately using "FIPS 186-2".

static const struct def_algo_rsa_sigver_caps openssl_rsa_1536_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1536,
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
} };

static const struct def_algo_rsa_sigver_caps openssl_rsa_1536_x931_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1536,
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,
} };

static const struct def_algo_rsa_sigver openssl_rsa_186_2_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_1536_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_1536_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_1536_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_1536_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_ANSIX931,
	.capabilities = openssl_rsa_1536_x931_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_1536_x931_sigver_caps),
} };

#define OPENSSL_RSA_186_2_SIGVER					\
	GENERIC_RSA_LEGACY_SIGVER(openssl_rsa_186_2_sigver,		\
				  ARRAY_SIZE(openssl_rsa_186_2_sigver))

const struct def_algo_kas_ifc_schema openssl_kas_ifc_schema_kts[] = { {
	.schema = DEF_ALG_KAS_IFC_KTS_OAEP_BASIC,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.kts_method = {
		// Normally, we have a distinct OPENSSL_3 definition when
		// ACVP_SHA512224 or ACVP_SHA512256 are used (preserving
		// backwards-compatibility with OpenSSL 1.0.x). However, because
		// these truncated hashes were actually added in OpenSSL 1.1.1,
		// the same release as OAEP, we can get away with it here.
		.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |
			   ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			   ACVP_SHA3_512,
		.supports_null_association_data = true,
		.associated_data_pattern_type = {
			DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO
			},
		.associated_data_pattern_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.length = 768,
} };

#define OPENSSL_RSA_OAEP						\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(openssl_rsa_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARTIALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
					  DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,\
					  DEF_ALG_KAS_IFC_RSAKPG1_CRT,	\
					  DEF_ALG_KAS_IFC_RSAKPG2_BASIC,\
					  DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR,\
					  DEF_ALG_KAS_IFC_RSAKPG2_CRT },\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_2048,		\
				       DEF_ALG_RSA_MODULO_3072,		\
				       DEF_ALG_RSA_MODULO_4096,		\
				       DEF_ALG_RSA_MODULO_6144,		\
				       DEF_ALG_RSA_MODULO_8192 },	\
		.keygen.fixedpubexp = "010001",				\
		.schema = openssl_kas_ifc_schema_kts,			\
		.schema_num = ARRAY_SIZE(openssl_kas_ifc_schema_kts),	\
		},							\
	}

/**************************************************************************
 * ECDSA Definitions
 **************************************************************************/
#define NISTP_CURVES 	ACVP_NISTP224 | ACVP_NISTP256 |			\
			ACVP_NISTP384 | ACVP_NISTP521
#define NISTB_CURVES 	ACVP_NISTB233 | ACVP_NISTB283 |			\
			ACVP_NISTB409 | ACVP_NISTB571
#define NISTK_CURVES 	ACVP_NISTK233 | ACVP_NISTK283 |			\
			ACVP_NISTK409 | ACVP_NISTK571

#define OPENSSL_ECDSA_KEYGEN(rev, curves)				\
	GENERIC_ECDSA_KEYGEN(rev, curves, DEF_ALG_ECDSA_TESTING_CANDIDATES)
#define OPENSSL_ECDSA_KEYVER(rev, curves)				\
	GENERIC_ECDSA_KEYVER(rev, curves)
#define OPENSSL_ECDSA_SIGGEN(rev, curves, hashes)			\
	GENERIC_ECDSA_SIGGEN(rev, curves, hashes, false),		\
	GENERIC_ECDSA_SIGGEN(rev, curves, hashes, true)
#define OPENSSL_ECDSA_SIGVER(rev, curves, hashes)			\
	GENERIC_ECDSA_SIGVER(rev, curves, hashes, false)

/**************************************************************************
 * EDDSA Definitions
 **************************************************************************/
#define OPENSSL_EDDSA_KEYGEN(curves)					\
	GENERIC_EDDSA_KEYGEN(curves)
#define OPENSSL_EDDSA_SIGGEN(curves, prehash)				\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGGEN,	\
			DEF_PREREQS(generic_eddsa_prereqs),		\
			.curve = curves,				\
			.eddsa_pure = DEF_ALG_EDDSA_PURE_SUPPORTED,	\
			.eddsa_prehash = prehash,			\
			/* Versions below 3.2.0 don't support context */\
			.context_length = { DEF_ALG_ZERO_VALUE }	\
			}						\
		}							\
	}
#define OPENSSL_3_2_EDDSA_SIGGEN(curves, prehash)			\
	GENERIC_EDDSA_SIGGEN(curves, DEF_ALG_EDDSA_PURE_SUPPORTED, prehash)
#define OPENSSL_EDDSA_SIGVER(curves, prehash)				\
	GENERIC_EDDSA_SIGVER(curves, DEF_ALG_EDDSA_PURE_SUPPORTED, prehash)

/**************************************************************************
 * DSA Definitions
 **************************************************************************/
#define OPENSSL_DSA_PQG_COMMON(x, L, N, hashes, g_gen_method)		\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = x,					\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.dsa_pq_gen_method = DEF_ALG_DSA_PROBABLE_PQ_GEN, \
			.dsa_g_gen_method = g_gen_method, 		\
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define OPENSSL_DSA_PQGGEN(L, N, hashes, g_gen_method)			\
		OPENSSL_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGGEN, L, N, hashes, g_gen_method)
#define OPENSSL_DSA_PQGVER(L, N, hashes, g_gen_method)			\
		OPENSSL_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGVER, L, N, hashes, g_gen_method)

#define OPENSSL_DSA_KEYGEN(L, N)					\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_KEYGEN,		\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			}						\
		}							\
	}

#define OPENSSL_DSA_SIGGEN(L, N, hashes)				\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_SIGGEN,		\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define OPENSSL_DSA_SIGVER(L, N, hashes)				\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_SIGVER,		\
			.dsa_l = L,		 			\
			.dsa_n = N,					\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.hashalg = hashes,				\
			}						\
		}							\
	}

/**************************************************************************
 * ECDH Definitions
 **************************************************************************/
#if 0
static const struct def_algo_prereqs openssl_ecdh_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
	{
		.algorithm = "ECDSA",
		.valvalue = "same"
	},
};

static const struct def_algo_kas_ecc_nokdfnokc openssl_kas_ecc_nokdfnokc_eb = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_EB,
	.curve = ACVP_NISTP224,
	.hashalg = ACVP_SHA224
};

static const struct def_algo_kas_ecc_nokdfnokc openssl_kas_ecc_nokdfnokc_ec = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_EC,
	.curve = ACVP_NISTP256,
	.hashalg = ACVP_SHA256
};

static const struct def_algo_kas_ecc_nokdfnokc openssl_kas_ecc_nokdfnokc_ed = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_ED,
	.curve = ACVP_NISTP384,
	.hashalg = ACVP_SHA384
};

static const struct def_algo_kas_ecc_nokdfnokc openssl_kas_ecc_nokdfnokc_ee = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_EE,
	.curve = ACVP_NISTP521,
	.hashalg = ACVP_SHA512
};

static const struct def_algo_kas_ecc_cdh_component openssl_kas_ecc_cdh = {
	.curves = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521
};

#define __OPENSSL_KAS_ECC(paramset)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC,					\
	.algo.kas_ecc = {						\
		DEF_PREREQS(openssl_ecdh_prereqs),			\
		.kas_ecc_function = DEF_ALG_KAS_ECC_PARTIALVAL,		\
		.kas_ecc_schema = DEF_ALG_KAS_ECC_EPHEMERAL_UNIFIED,	\
		.kas_ecc_role = DEF_ALG_KAS_ECC_INITIATOR |		\
				DEF_ALG_KAS_ECC_RESPONDER,		\
		.kas_ecc_dh_type = DEF_ALG_KAS_ECC_NO_KDF_NO_KC,	\
		.type_info.nokdfnokc = paramset,			\
		},							\
	}

#define OPENSSL_KAS_ECC							\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_eb),		\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ec),		\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ed),		\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ee)

#define OPENSSL_KAS_ECC_CDH						\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC,					\
	.algo.kas_ecc = {						\
		DEF_PREREQS(openssl_ecdh_prereqs),			\
		.kas_ecc_schema = DEF_ALG_KAS_ECC_CDH_COMPONENT,	\
		.kas_ecc_function = DEF_ALG_KAS_ECC_KEYPAIRGEN,		\
		.kas_ecc_dh_type = DEF_ALG_KAS_ECC_CDH,			\
		.type_info.cdh_component = &openssl_kas_ecc_cdh		\
		}							\
	}

/**************************************************************************
 * FFC DH Definitions
 **************************************************************************/
// static const struct def_algo_prereqs openssl_ffc_prereqs[] = {
// 	{
// 		.algorithm = "SHA",
// 		.valvalue = "same"
// 	},
// 	{
// 		.algorithm = "DRBG",
// 		.valvalue = "same"
// 	},
// 	{
// 		.algorithm = "DSA",
// 		.valvalue = "same"
// 	},
// };
//
// static const struct def_algo_kas_ffc_nokdfnokc openssl_kas_ffc_nokdfnokc_fb = {
// 	.kas_ffc_paramset = DEF_ALG_KAS_FFC_FB,
// 	.hashalg = ACVP_SHA224
// };
//
// static const struct def_algo_kas_ffc_nokdfnokc openssl_kas_ffc_nokdfnokc_fc = {
// 	.kas_ffc_paramset = DEF_ALG_KAS_FFC_FC,
// 	.hashalg = ACVP_SHA256
// };

#define __OPENSSL_KAS_FFC(paramset)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_FFC,					\
	.algo.kas_ffc = {						\
		DEF_PREREQS(openssl_ffc_prereqs),			\
		.kas_ffc_function = DEF_ALG_KAS_FFC_FULLVAL,		\
		.kas_ffc_schema = DEF_ALG_KAS_FFC_DH_EPHEM,		\
		.kas_ffc_role = DEF_ALG_KAS_FFC_INITIATOR |		\
				DEF_ALG_KAS_FFC_RESPONDER,		\
		.kas_ffc_dh_type = DEF_ALG_KAS_FFC_NO_KDF_NO_KC,	\
		.type_info.nokdfnokc = paramset,			\
		},							\
	}

#define OPENSSL_KAS_FFC							\
	__OPENSSL_KAS_FFC(&openssl_kas_ffc_nokdfnokc_fb),		\
	__OPENSSL_KAS_FFC(&openssl_kas_ffc_nokdfnokc_fc)
#endif

/**************************************************************************
 * SP800-56A REV3
 **************************************************************************/
#define OPENSSL_KAS_ECC_SSC_R3(curves)					\
	GENERIC_KAS_ECC_SSC_R3(curves)

#define OPENSSL_KAS_FFC_SSC_R3						\
	GENERIC_KAS_FFC_SSC_R3(ACVP_DH_FB | ACVP_DH_FC |		\
			       ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |	\
			       ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |	\
			       ACVP_DH_MODP_8192 | ACVP_DH_FFDHE_2048 |	\
			       ACVP_DH_FFDHE_3072 | ACVP_DH_FFDHE_4096 |\
			       ACVP_DH_FFDHE_6144 | ACVP_DH_FFDHE_8192)

#define OPENSSL_SAFEPRIMES						\
	GENERIC_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYGENERATION,		\
			   ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |	\
			   ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |	\
			   ACVP_DH_MODP_8192 | ACVP_DH_FFDHE_2048 |	\
			   ACVP_DH_FFDHE_3072 | ACVP_DH_FFDHE_4096 |	\
			   ACVP_DH_FFDHE_6144 | ACVP_DH_FFDHE_8192),	\
	GENERIC_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYVERIFICATION,		\
			   ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |	\
			   ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |	\
			   ACVP_DH_MODP_8192 | ACVP_DH_FFDHE_2048 |	\
			   ACVP_DH_FFDHE_3072 | ACVP_DH_FFDHE_4096 |	\
			   ACVP_DH_FFDHE_6144 | ACVP_DH_FFDHE_8192)

/**************************************************************************
 * SP800-56B REV2
 **************************************************************************/

const struct def_algo_kas_ifc_ssc_schema openssl_kas_ifc_ssc_schema[] = { {
	.schema = DEF_ALG_KAS_IFC_SSC_KAS1,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER
}, {
	.schema = DEF_ALG_KAS_IFC_SSC_KAS2,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER
} };

#define OPENSSL_RSA_SSC							\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(openssl_rsa_prereqs),			\
		.function = DEF_ALG_KAS_IFC_SSC,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
					  DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,\
					  DEF_ALG_KAS_IFC_RSAKPG1_CRT,	\
					  DEF_ALG_KAS_IFC_RSAKPG2_BASIC,\
					  DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR,\
					  DEF_ALG_KAS_IFC_RSAKPG2_CRT },\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_2048,		\
				       DEF_ALG_RSA_MODULO_3072,		\
				       DEF_ALG_RSA_MODULO_4096,		\
				       DEF_ALG_RSA_MODULO_6144,		\
				       DEF_ALG_RSA_MODULO_8192 },	\
		.keygen.fixedpubexp = "010001",				\
		.ssc_schema = openssl_kas_ifc_ssc_schema,		\
		.ssc_schema_num = ARRAY_SIZE(openssl_kas_ifc_ssc_schema),\
		},							\
	}

/**************************************************************************
 * SP800-56C rev 2 OneStep KDF
 **************************************************************************/
static const struct def_algo_prereqs openssl_kdf_onestep_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "KMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON				\
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |		\
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM

const struct def_algo_kas_kdf_onestepkdf_aux openssl_kas_kdf_onestepkdf_aux[] = { {
	.auxfunc = ACVP_SHA1,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA384,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA512,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA512224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA512256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA3_224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA3_256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA3_384,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_SHA3_512,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA1,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_384,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_512,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_512224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA2_512256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA3_224,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA3_256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA3_384,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_HMACSHA3_512,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_KMAC128,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
}, {
	.auxfunc = ACVP_KMAC256,
	OPENSSL_KAS_KDF_ONESTEPKDF_AUX_COMMON
} };


#define OPENSSL_KDA_ONESTEP						\
	{								\
	.type = DEF_ALG_TYPE_KDF_ONESTEP,				\
	.algo.kdf_onestep = {						\
		DEF_PREREQS(openssl_kdf_onestep_prereqs),		\
		.kdf_spec = DEF_ALG_KDF_SP800_56Crev2,			\
		.onestep = {						\
			.aux_function = openssl_kas_kdf_onestepkdf_aux,	\
			.aux_function_num = ARRAY_SIZE(openssl_kas_kdf_onestepkdf_aux),\
			.fixed_info_pattern_type = {			\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO },\
		},							\
		.length = 2048,						\
		DEF_ALG_DOMAIN(.zlen, 224, 8192, 8),			\
		}							\
	}

/**************************************************************************
 * SP800-56C rev 2 TwoStep KDF
 **************************************************************************/
static const struct def_algo_prereqs openssl_kdf_twostep_prereqs[] = {
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

const struct def_algo_kas_kdf_twostepkdf openssl_kas_kdf_twostepkdf[] = { {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO },
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_FEEDBACK,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512 | ACVP_HMACSHA2_512224 |
			  ACVP_HMACSHA2_512256 | ACVP_HMACSHA3_224 |
			  ACVP_HMACSHA3_256 | ACVP_HMACSHA3_384 |
			  ACVP_HMACSHA3_512,
		.supported_lengths = { 2048 },
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_AFTER_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_8,
		.supports_empty_iv = true,
		.requires_empty_iv = true
	}
} };

#define OPENSSL_KDA_TWOSTEP						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TWOSTEP,				\
	.algo.kdf_twostep = {						\
		DEF_PREREQS(openssl_kdf_twostep_prereqs),		\
		.kdf_spec = DEF_ALG_KDF_SP800_56Crev2,			\
		.twostep = openssl_kas_kdf_twostepkdf,			\
		.twostep_num = ARRAY_SIZE(openssl_kas_kdf_twostepkdf),	\
		.length = 2048,						\
		DEF_ALG_DOMAIN(.zlen, 224, 8192, 8),			\
		.hybrid_shared_secret = false,				\
		},							\
	}

/**************************************************************************
 * TLS Definitions
 **************************************************************************/
#define OPENSSL_TLS11_KDF	GENERIC_TLS11_KDF
#define OPENSSL_TLS12_KDF	GENERIC_TLS12_KDF
#define OPENSSL_TLS13_KDF	GENERIC_TLS13_KDF

#define OPENSSL_HKDF							\
	GENERIC_HKDF(ACVP_SHA1 |					\
		     ACVP_SHA224 | ACVP_SHA256 |			\
		     ACVP_SHA384 | ACVP_SHA512 |			\
		     ACVP_SHA512224 | ACVP_SHA512256 |			\
		     ACVP_SHA3_224 | ACVP_SHA3_256 |			\
		     ACVP_SHA3_384 | ACVP_SHA3_512)

/**************************************************************************
 * SSH KDF Definitions
 **************************************************************************/
#define OPENSSL_KDF_SSH							\
	GENERIC_SSH_KDF_AES, GENERIC_SSH_KDF_TDES

/**************************************************************************
 * SP800-132 PBKDF Definitions
 **************************************************************************/
#define OPENSSL_PBKDF(x)	GENERIC_PBKDF(x)

/**************************************************************************
 * SP800-108 KDF Definitions
 **************************************************************************/
#define OPENSSL_KBKDF_CMAC_AES						\
	GENERIC_KBKDF_CTR_AES(DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			      DEF_ALG_KDF_108_COUNTER_LENGTH_32),	\
	GENERIC_KBKDF_FB_AES(DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			     DEF_ALG_KDF_108_COUNTER_LENGTH_32)

#define OPENSSL_KBKDF_CMAC_TDES						\
	GENERIC_KBKDF_CTR_TDES(DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			       DEF_ALG_KDF_108_COUNTER_LENGTH_32),	\
	GENERIC_KBKDF_FB_TDES(DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			      DEF_ALG_KDF_108_COUNTER_LENGTH_32)

#define OPENSSL_KBKDF_HMAC						\
	GENERIC_KBKDF_CTR_HMAC(ACVP_HMACSHA1 |				\
			       ACVP_HMACSHA2_224 | ACVP_HMACSHA2_256 |	\
			       ACVP_HMACSHA2_384 | ACVP_HMACSHA2_512 |	\
			       ACVP_HMACSHA2_512224 |			\
			       ACVP_HMACSHA2_512256 |			\
			       ACVP_HMACSHA3_224 | ACVP_HMACSHA3_256 |	\
			       ACVP_HMACSHA3_384 | ACVP_HMACSHA3_512,	\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			       DEF_ALG_KDF_108_COUNTER_LENGTH_32),	\
	GENERIC_KBKDF_FB_HMAC(ACVP_HMACSHA1 |				\
			      ACVP_HMACSHA2_224 | ACVP_HMACSHA2_256 |	\
			      ACVP_HMACSHA2_384 | ACVP_HMACSHA2_512 |	\
			      ACVP_HMACSHA2_512224 |			\
			      ACVP_HMACSHA2_512256 |			\
			      ACVP_HMACSHA3_224 | ACVP_HMACSHA3_256 |	\
			      ACVP_HMACSHA3_384 | ACVP_HMACSHA3_512,	\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			      DEF_ALG_KDF_108_COUNTER_LENGTH_32)

#define OPENSSL_KBKDF_KMAC						\
	GENERIC_KBKDF_KMAC(ACVP_KMAC128 | ACVP_KMAC256)

/**************************************************************************
 * ANSI X9.42 Definitions
 **************************************************************************/
#define OPENSSL_ANSI_X942						\
	GENERIC_X942_DER_AES_KDF(ACVP_SHA1 |				\
				 ACVP_SHA224 | ACVP_SHA256 |		\
				 ACVP_SHA384 | ACVP_SHA512 |		\
				 ACVP_SHA512224 | ACVP_SHA512256)

#define OPENSSL_ANSI_X942_SHA3						\
	GENERIC_X942_DER_AES_KDF(ACVP_SHA3_224 | ACVP_SHA3_256 |	\
				 ACVP_SHA3_384 | ACVP_SHA3_512)

/**************************************************************************
 * ANSI X9.63 Definitions
 **************************************************************************/
#define OPENSSL_ANSI_X963						\
	GENERIC_X963_KDF(ACVP_SHA224 | ACVP_SHA256 |			\
			 ACVP_SHA384 | ACVP_SHA512 |			\
			 ACVP_SHA512224 | ACVP_SHA512256)

#define OPENSSL_ANSI_X963_SHA3						\
	GENERIC_X963_KDF(ACVP_SHA3_224 | ACVP_SHA3_256 |		\
			 ACVP_SHA3_384 | ACVP_SHA3_512)

/**************************************************************************
 * XOF definitions
 **************************************************************************/
#define OPENSSL_KMAC(kmac_def)						\
	{								\
	.type = DEF_ALG_TYPE_XOF,					\
	.algo = {							\
		.xof = {						\
			.algorithm = kmac_def,				\
			.xof = DEF_ALG_XOF_NOT_PRESENT |		\
			       DEF_ALG_XOF_PRESENT,			\
			.hex = true,					\
			DEF_ALG_DOMAIN(.messagelength, 0, 65536, 8),	\
			DEF_ALG_DOMAIN(.outlength, 16, 65536, 8),	\
			DEF_ALG_DOMAIN(.keylength, 128, 1024, 8),	\
			DEF_ALG_DOMAIN(.maclength, 32, 65536, 8),	\
			}						\
		},							\
	}

/**************************************************************************
 * OpenSSL Generic Definitions
 **************************************************************************/
static const struct def_algo openssl_tdes [] = {
	OPENSSL_TDES_CFB64,
	OPENSSL_TDES_CFB8,
	OPENSSL_TDES_CFB1,
	OPENSSL_TDES_OFB,
	OPENSSL_TDES_CBC,
	OPENSSL_TDES_ECB,

	OPENSSL_CMAC_TDES
};

static const struct def_algo openssl_3_tdes [] = {
	OPENSSL_TDES_CBC,
	OPENSSL_TDES_ECB,

	OPENSSL_CMAC_TDES
};

static const struct def_algo openssl_aes [] = {
	OPENSSL_AES_OFB,
	OPENSSL_AES_CFB1,
	OPENSSL_AES_CFB8,
	OPENSSL_AES_CFB128,
	OPENSSL_AES_ECB,
	OPENSSL_AES_CBC,
	OPENSSL_AES_XTS,
	OPENSSL_AES_CTR,
	OPENSSL_AES_KW,
	OPENSSL_AES_KWP,

	OPENSSL_AES_CCM,

	OPENSSL_CMAC_AES,

	/* Built-in DRBG in crypto/rand/ */
	OPENSSL_DRBG_CTR(true),
};

static const struct def_algo openssl_3_aes [] = {
	OPENSSL_AES_OFB,
	OPENSSL_AES_CFB1,
	OPENSSL_AES_CFB8,
	OPENSSL_AES_CFB128,
	OPENSSL_AES_ECB,
	OPENSSL_AES_CBC,
	OPENSSL_AES_CBC_CS1,
	OPENSSL_AES_CBC_CS2,
	OPENSSL_AES_CBC_CS3,
	OPENSSL_AES_XTS,
	OPENSSL_AES_CTR,
	OPENSSL_AES_KW,
	OPENSSL_AES_KWP,

	OPENSSL_AES_CCM,

	OPENSSL_CMAC_AES,
};

static const struct def_algo openssl_gcm [] = {
	OPENSSL_AES_GCM,
	OPENSSL_AES_GCM_IIV,
};

static const struct def_algo openssl_ffc_dh [] = {
	//SP800-56A rev 1 is not supported any more (arbitrary primes are
	//rejected)
	//OPENSSL_KAS_FFC,
	OPENSSL_KAS_FFC_SSC_R3,
	OPENSSL_SAFEPRIMES,
};

#define OPENSSL_SHA_COMMON						\
	OPENSSL_SHA(ACVP_SHA1),						\
	OPENSSL_SHA(ACVP_SHA224),					\
	OPENSSL_SHA(ACVP_SHA256),					\
	OPENSSL_SHA(ACVP_SHA384),					\
	OPENSSL_SHA(ACVP_SHA512),					\
									\
	OPENSSL_HMAC(ACVP_HMACSHA1),					\
	OPENSSL_HMAC(ACVP_HMACSHA2_224),				\
	OPENSSL_HMAC(ACVP_HMACSHA2_256),				\
	OPENSSL_HMAC(ACVP_HMACSHA2_384),				\
	OPENSSL_HMAC(ACVP_HMACSHA2_512),				\
									\
	OPENSSL_RSA_186_2_SIGVER,					\
	OPENSSL_RSA_OAEP,						\
	OPENSSL_RSA_SSC,						\
									\
	OPENSSL_ECDSA_KEYGEN(DEF_ALG_ECDSA_186_5, NISTP_CURVES),	\
	OPENSSL_ECDSA_KEYVER(DEF_ALG_ECDSA_186_5, NISTP_CURVES),	\
	OPENSSL_ECDSA_KEYVER(DEF_ALG_ECDSA_186_4, ACVP_NISTP192),	\
									\
	/* OPENSSL_KAS_ECC, */						\
	/* OPENSSL_KAS_ECC_CDH, */					\
	OPENSSL_KAS_ECC_SSC_R3(NISTP_CURVES)

#define OPENSSL_1_SHA_COMMON						\
	OPENSSL_SHA_COMMON,						\
									\
	OPENSSL_RSA_KEYGEN,						\
	OPENSSL_RSA_SIGGEN,						\
	OPENSSL_RSA_SIGVER,						\
	OPENSSL_RSA_186_4_SIGVER,					\
									\
	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_5, NISTP_CURVES,		\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512),				\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_5, NISTP_CURVES,		\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512),				\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTP192,	\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512),				\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, 			\
			     ACVP_NISTP192 | NISTP_CURVES, ACVP_SHA1),	\
									\
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,	\
			   ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			   ACVP_SHA512, DEF_ALG_DSA_UNVERIFIABLE_G_GEN),\
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,	\
			   DEF_ALG_DSA_UNVERIFIABLE_G_GEN),		\
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,	\
			   DEF_ALG_DSA_UNVERIFIABLE_G_GEN),		\
	/* TODO OpenSSL SLES does not have 1024 bits, RHEL has it	\
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160, 	\
			   ACVP_SHA1, DEF_ALG_DSA_UNVERIFIABLE_G_GEN),*/\
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224, 	\
			   ACVP_SHA224, DEF_ALG_DSA_UNVERIFIABLE_G_GEN),\
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, 	\
			   ACVP_SHA256, DEF_ALG_DSA_UNVERIFIABLE_G_GEN),\
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA256, DEF_ALG_DSA_UNVERIFIABLE_G_GEN),\
									\
	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224),	\
	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256),	\
	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256),	\
									\
	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,	\
			   ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			   ACVP_SHA512),				\
	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),	\
	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),	\
									\
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160,	\
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |	\
			   ACVP_SHA384 | ACVP_SHA512),			\
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,	\
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |	\
			   ACVP_SHA384 | ACVP_SHA512),			\
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |	\
			   ACVP_SHA384 | ACVP_SHA512),			\
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,	\
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |	\
			   ACVP_SHA384 | ACVP_SHA512),			\
									\
	OPENSSL_TLS11_KDF,						\
	OPENSSL_TLS12_KDF,						\
									\
	OPENSSL_PBKDF(ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |		\
		      ACVP_SHA384 | ACVP_SHA512)

#define OPENSSL_3_SHA_COMMON						\
	OPENSSL_SHA_COMMON,						\
									\
	OPENSSL_SHA(ACVP_SHA512224),					\
	OPENSSL_SHA(ACVP_SHA512256),					\
									\
	OPENSSL_HMAC(ACVP_HMACSHA2_512224),				\
	OPENSSL_HMAC(ACVP_HMACSHA2_512256),				\
									\
	OPENSSL_3_RSA_KEYGEN,						\
	OPENSSL_3_RSA_SIGGEN,						\
	OPENSSL_3_RSA_SIGVER,						\
	OPENSSL_3_RSA_186_4_SIGVER,					\
									\
	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_5, NISTP_CURVES,		\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256),\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_5, NISTP_CURVES,		\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256),\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTP192,	\
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |	\
			     ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256),\
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, 			\
			     ACVP_NISTP192 | NISTP_CURVES, ACVP_SHA1),	\
									\
	OPENSSL_TLS12_KDF,						\
									\
	OPENSSL_PBKDF(ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |		\
		      ACVP_SHA384 | ACVP_SHA512 | ACVP_SHA512224 |	\
		      ACVP_SHA512256),					\
									\
	OPENSSL_ANSI_X942,						\
	OPENSSL_ANSI_X963,						\
	OPENSSL_KDF_SSH

static const struct def_algo openssl_sha [] = {
	OPENSSL_1_SHA_COMMON
};

static const struct def_algo openssl_3_sha [] = {
	OPENSSL_3_SHA_COMMON
};

static const struct def_algo openssl_sha_power_isa [] = {
	OPENSSL_1_SHA_COMMON
};

static const struct def_algo openssl_3_sha_power_isa [] = {
	OPENSSL_3_SHA_COMMON
};

static const struct def_algo openssl_ssh [] = {
	OPENSSL_KDF_SSH
};

static const struct def_algo openssl_sha3 [] = {
	OPENSSL_SHA(ACVP_SHA3_224),
	OPENSSL_SHA(ACVP_SHA3_256),
	OPENSSL_SHA(ACVP_SHA3_384),
	OPENSSL_SHA(ACVP_SHA3_512),

	OPENSSL_HMAC(ACVP_HMACSHA3_224),
	OPENSSL_HMAC(ACVP_HMACSHA3_256),
	OPENSSL_HMAC(ACVP_HMACSHA3_384),
	OPENSSL_HMAC(ACVP_HMACSHA3_512),

	OPENSSL_SHAKE(ACVP_SHAKE128),
	OPENSSL_SHAKE(ACVP_SHAKE256),

	OPENSSL_PBKDF(ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
		      ACVP_SHA3_512),

	OPENSSL_RSA_SHA3_SIGGEN,
	OPENSSL_RSA_SHA3_SIGVER,

	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_5, NISTP_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_5, NISTP_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTP192,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
};

static const struct def_algo openssl_3_sha3 [] = {
	OPENSSL_SHA(ACVP_SHA3_224),
	OPENSSL_SHA(ACVP_SHA3_256),
	OPENSSL_SHA(ACVP_SHA3_384),
	OPENSSL_SHA(ACVP_SHA3_512),

	OPENSSL_HMAC(ACVP_HMACSHA3_224),
	OPENSSL_HMAC(ACVP_HMACSHA3_256),
	OPENSSL_HMAC(ACVP_HMACSHA3_384),
	OPENSSL_HMAC(ACVP_HMACSHA3_512),

	OPENSSL_ANSI_X942_SHA3,
	OPENSSL_ANSI_X963_SHA3,

	OPENSSL_KMAC(ACVP_KMAC128),
	OPENSSL_KMAC(ACVP_KMAC256),

	OPENSSL_SHAKE(ACVP_SHAKE128),
	OPENSSL_SHAKE(ACVP_SHAKE256),

	OPENSSL_PBKDF(ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
		      ACVP_SHA3_512),

	OPENSSL_RSA_SHA3_SIGGEN,
	OPENSSL_RSA_SHA3_SIGVER,

	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_5, NISTP_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_5, NISTP_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTP192,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
};

static const struct def_algo openssl_10x_drbg [] = {
	/* DRBG in crypto/fips/ */
	// Does OpenSSL 1.0.x support reseed? Past definitions didn't test it.
	OPENSSL_DRBG_CTR(false),
	OPENSSL_DRBG_HMAC(false),
	OPENSSL_DRBG_HASH(false),
};

static const struct def_algo openssl_3_drbg [] = {
	/* DRBG in providers/implementations/rands/ */
	OPENSSL_DRBG_CTR(true),
	OPENSSL_3_DRBG_HMAC,
	OPENSSL_3_DRBG_HASH,
};

static const struct def_algo openssl_kbkdf [] = {
	OPENSSL_KBKDF_HMAC,
	OPENSSL_KBKDF_CMAC_AES,
	OPENSSL_KBKDF_CMAC_TDES,
};

static const struct def_algo openssl_3_1_kbkdf [] = {
	OPENSSL_KBKDF_HMAC,
	OPENSSL_KBKDF_CMAC_AES,
	OPENSSL_KBKDF_KMAC,
};

static const struct def_algo openssl_kda [] = {
	OPENSSL_KDA_ONESTEP,
	OPENSSL_KDA_TWOSTEP
};

static const struct def_algo openssl_neon [] = {
	OPENSSL_SHA(ACVP_SHA256),
	OPENSSL_HMAC(ACVP_HMACSHA2_256),
};

static const struct def_algo openssl_tls13 [] = {
	OPENSSL_TLS13_KDF,
	OPENSSL_HKDF
};

static const struct def_algo openssl_eddsa [] = {
	/* OpenSSL 1.1.1, 3.0 and 3.1 */
	OPENSSL_EDDSA_KEYGEN(ACVP_ED25519 | ACVP_ED448),
	OPENSSL_EDDSA_SIGGEN(ACVP_ED25519 | ACVP_ED448,
			     DEF_ALG_EDDSA_PREHASH_UNSUPPORTED),
	OPENSSL_EDDSA_SIGVER(ACVP_ED25519 | ACVP_ED448,
			     DEF_ALG_EDDSA_PREHASH_UNSUPPORTED),
};

static const struct def_algo openssl_3_2_eddsa [] = {
	/* OpenSSL 3.2+ */
	OPENSSL_EDDSA_KEYGEN(ACVP_ED25519 | ACVP_ED448),
	OPENSSL_3_2_EDDSA_SIGGEN(ACVP_ED25519 | ACVP_ED448,
				 DEF_ALG_EDDSA_PREHASH_SUPPORTED),
	OPENSSL_EDDSA_SIGVER(ACVP_ED25519 | ACVP_ED448,
			     DEF_ALG_EDDSA_PREHASH_SUPPORTED),
};

static const struct def_algo openssl_ecdsa_BK_curves [] = {
	OPENSSL_ECDSA_KEYGEN(DEF_ALG_ECDSA_186_4, NISTB_CURVES | NISTK_CURVES),
	OPENSSL_ECDSA_KEYVER(DEF_ALG_ECDSA_186_4, ACVP_NISTB163 | NISTB_CURVES |
						  ACVP_NISTK163 | NISTK_CURVES),
	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_4, NISTB_CURVES | NISTK_CURVES,
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			     ACVP_SHA512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTB163 | NISTB_CURVES |
						  ACVP_NISTK163 | NISTK_CURVES,
			     ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |
			     ACVP_SHA384 | ACVP_SHA512),
};

static const struct def_algo openssl_3_ecdsa_BK_curves [] = {
	OPENSSL_ECDSA_KEYGEN(DEF_ALG_ECDSA_186_4, NISTB_CURVES | NISTK_CURVES),
	OPENSSL_ECDSA_KEYVER(DEF_ALG_ECDSA_186_4, ACVP_NISTB163 | NISTB_CURVES |
						  ACVP_NISTK163 | NISTK_CURVES),
	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_4, NISTB_CURVES | NISTK_CURVES,
			     ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			     ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTB163 | NISTB_CURVES |
						  ACVP_NISTK163 | NISTK_CURVES,
			     ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 |
			     ACVP_SHA384 | ACVP_SHA512 | ACVP_SHA512224 |
			     ACVP_SHA512256),
};

static const struct def_algo openssl_ecdsa_sha3_BK_curves [] = {
	OPENSSL_ECDSA_SIGGEN(DEF_ALG_ECDSA_186_4, NISTB_CURVES | NISTK_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
	OPENSSL_ECDSA_SIGVER(DEF_ALG_ECDSA_186_4, ACVP_NISTB163 | NISTB_CURVES |
						  ACVP_NISTK163 | NISTK_CURVES,
			     ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
			     ACVP_SHA3_512),
};

static const struct def_algo openssl_ecdh_BK_curves [] = {
	OPENSSL_KAS_ECC_SSC_R3(NISTB_CURVES | NISTK_CURVES),
};

/**************************************************************************
 * Register operation
 **************************************************************************/

#define OPENSSL_IMPL_COMMON(impl1, impl3, proc, impl_name, impl_description) \
	IMPLEMENTATION(impl1, "OpenSSL", proc, impl_name, impl_description), \
	IMPLEMENTATION(impl3, "3_OpenSSL", proc, impl_name, impl_description)

#define OPENSSL_IMPL_SHA(proc, imple_name, imple_description)		\
	OPENSSL_IMPL_COMMON(openssl_sha, openssl_3_sha,			\
			    proc, imple_name, imple_description)

#define OPENSSL_IMPL_SHA_POWER(proc, imple_name, imple_description)	\
	OPENSSL_IMPL_COMMON(openssl_sha_power_isa, openssl_3_sha_power_isa,\
			    proc, imple_name, imple_description)

static struct def_algo_map openssl_algo_map [] = {
	/* OpenSSL TDES C implementation **************************************/
	OPENSSL_IMPL_COMMON(openssl_tdes, openssl_3_tdes, "", "TDES_C",
			    "Generic C non-optimized TDES implementation"),
	/* OpenSSL KBKDF implementation ***************************************/
	OPENSSL_IMPL_COMMON(openssl_kbkdf, openssl_kbkdf, "", "KBKDF",
			    "Generic C non-optimized KBKDF implementation"),
	/* OpenSSL KDA implementation *****************************************/
	OPENSSL_IMPL_COMMON(openssl_kda, openssl_kda, "", "KDA",
			    "Generic C non-optimized KDA implementation"),
	/* OpenSSL ECC all curves implementation ******************************/
	OPENSSL_IMPL_COMMON(openssl_ecdsa_BK_curves, openssl_3_ecdsa_BK_curves,
			    "", "ECDSA K/B", "ECDSA with K and B curves"),
	OPENSSL_IMPL_COMMON(openssl_ecdsa_sha3_BK_curves,
			    openssl_ecdsa_sha3_BK_curves,
			    "", "ECDSA SHA3 K/B",
			    "ECDSA with SHA3 and K and B curves"),
	OPENSSL_IMPL_COMMON(openssl_ecdh_BK_curves, openssl_ecdh_BK_curves,
			    "", "ECDH K/B", "ECDH with K and B curves"),
	/* OpenSSL TLS 1.3 implementation *************************************/
	OPENSSL_IMPL_COMMON(openssl_tls13, openssl_tls13, "",
			    "TLS v1.3", "TLS v1.3 implementation"),

	/* OpenSSL FFC DH implementation **************************************/
	OPENSSL_IMPL_COMMON(openssl_ffc_dh, openssl_ffc_dh, "", "FFC_DH",
			    "Generic C non-optimized DH implementation"),

	/* OpenSSL 1.1.1, 3.0, and 3.1 EdDSA implementation *******************/
	OPENSSL_IMPL_COMMON(openssl_eddsa, openssl_eddsa, "", "EDDSA",
			    "Generic EdDSA implementation"),

	/*
	 * OpenSSL 1.0.x upstream DRBG implementation that may have been
	 * forward-ported to 1.1.x (e.g. on RHEL8)
	 * The different instances relate to the different implementations of
	 * the underlying cipher
	 **********************************************************************/
	IMPLEMENTATION(openssl_10x_drbg, "OpenSSL", "", "DRBG_10X",
		       "Generic DRBG implementation with all types of DRBG"),

	/* OpenSSL 3 DRBG implementation **************************************/
	IMPLEMENTATION(openssl_3_drbg, "3_OpenSSL", "", "DRBG_3",
		       "Generic DRBG implementation with all types of DRBG"),

	/* OpenSSL 3.2+ EdDSA implementation **********************************/
	IMPLEMENTATION(openssl_3_2_eddsa, "3_OpenSSL", "", "EDDSA_3_2",
		       "Generic EdDSA implementation"),

	/* OpenSSL 3.1+ KBKDF implementation **********************************/
	IMPLEMENTATION(openssl_3_1_kbkdf, "3_OpenSSL", "", "KBKDF_3_1",
		       "Generic C non-optimized KBKDF implementation"),

	/* OpenSSL has support for 5 different types of AES implementations.
	 * These implementations are selected in an order of precedence, i.e. if
	 * the first implementation is available, it will be selected. Otherwise
	 * the second implementation will be selected, etc. etc.
	 *
	 * The order of precedence is as follows:
	 * 1) Any processor-specific AES implementation. Currently: AES-NI,
	 *    SPARC AES, s390x AES, RV64I ZKND/ZKNE, RV32I ZBKB/ZKND/ZKNE. For
	 *    x86, this means AES-NI.
	 * 2) HWAES implementations. This is indicated by HWAES_CAPABLE in the
	 *    source code. x86 does not have such an implementation, so we do
	 *    not define it.
	 * 3) Bit sliced implementation (PAA) of AES using a vector instruction
	 *    set. This is indicated by BSAES_CAPABLE in the source code. x86
	 *    does support this implementation, when SSSE3 is available (see
	 *    include/crypto/aes_platform.h where BSAES_CAPABLE is defined).
	 *    OpenSSL only uses this implementation for:
	 *    a) CTR encryption
	 *    b) CBC decryption
	 *    c) XTS
	 *    d) GCM
	 * 4) AES implementation (PAA) using vector permutation instructions.
	 *    This is indicated by VPAES_CAPABLE in the source code. x86 does
	 *    support this implementation, when SSSE3 is available (see
	 *    include/crypto/aes_platform.h where VPAES_CAPABLE is defined). As
	 *    it will be used when the mode is not one of a-d specified above,
	 *    we can combine it with the BSAES implementation.
	 * 5) Assembler implementation. This is the fallback implementation, and
	 *    only used when the accelerated implementations (above) are not
	 *    available. The assembler implementation is always available.
	 *
	 * Source: crypto/evp/e_aes.c (OpenSSL 1)
	 * Source: providers/implementations/ciphers/cipher_aes_hw.c (OpenSSL 3)
	 **********************************************************************/

	/* OpenSSL AESNI implementation ***************************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "X86", "AESNI",
			    "Intel AES-NI AES implementation"),
	/* OpenSSL AES constant time SSSE3 and bit sliced implementation ******/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "X86", "BAES_CTASM",
			    "Constant-time bit sliced/vector permutation AES implementation"),
	/* OpenSSL AES assembler implementation *******************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "X86", "AESASM",
			    "Assembler AES implementation"),

	/* Apart from the AES implementations, AES also has additional support
	 * for specific AES GCM implementations. This means, for each of the
	 * implementations described above, the GHASH part can also be hardware
	 * accelerated or implemented. Again, there is a precedence order. This
	 * order is different for each platform, but we will describe x86-64
	 * here.
	 *
	 * 1) AVX implementation (PAA). This path is taken if the PCLMULQDQ,
	 *    MOVBE, and AVX bits are all set in the CPUID. Uses the
	 *    gcm_init_avx function.
	 * 2) CLMUL implementation (PAA). This path is taken if the PCLMULQDQ
	 *    bit is set in the CPUID. Uses the gcm_init_clmul function.
	 * 3) 4-bit assembler implementation. This is the fallback
	 *    implementation. Uses the gcm_ghash_4bit function.
	 * NOTE: for AES-NI, the above precedence does not apply. Instead, there
	 * is either an AVX512+VAES implementation, or a regular AES-NI
	 * implementation. The AESNI definitions below are kept for historical
	 * reasons.
	 *
	 * Note that we also need to test each AES implementation as above! So
	 * for each of the 3 AES implementations, there will be 3 GHASH
	 * implementations, for a total of 9.
	 *
	 * Source: crypto/modes/gcm128.c
	 * Source: crypto/modes/asm/aes-gcm-avx512.pl
	 * Source: providers/implementations/ciphers/cipher_aes_gcm_hw_aesni.inc
	 **********************************************************************/

	/* OpenSSL AESNI with AVX GHASH multiplication implementation *********/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESNI_AVX",
			    "Intel AES-NI AES using GCM with AVX GHASH implementation"),
	/* OpenSSL AESNI with CLMUL GHASH multiplication implementation *******/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESNI_CLMULNI",
			    "Intel AES-NI AES using GCM with CLMUL GHASH implementation"),
	/* OpenSSL AESNI with 4-bit assembler GHASH multiplication
	 * implementation *****************************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESNI_ASM",
			    "Intel AES-NI AES using GCM with 4-bit assembler GHASH implementation"),
	/* OpenSSL AES constant time SSSE3 and bit sliced with AVX GHASH
	 * multiplication implementation **************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "BAES_CTASM_AVX",
			    "Constant-time bit sliced AES using GCM with AVX GHASH implementation"),
	/* OpenSSL AES constant time SSSE3 and bit sliced with CLMUL GHASH
	 * multiplication implementation **************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "BAES_CTASM_CLMULNI",
			    "Constant-time bit sliced AES using GCM with CLMUL GHASH implementation"),
	/* OpenSSL AES constant time SSSE3 and bit sliced with 4-bit assembler
	 * GHASH multiplication implementation ********************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "BAES_CTASM_ASM",
			    "Constant-time bit sliced AES using GCM with 4-bit assembler GHASH implementation"),
	/* OpenSSL AES assembler with AVX GHASH multiplication implementation */
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESASM_AVX",
			    "Assembler AES using GCM with AVX GHASH implementation"),
	/* OpenSSL AES assembler with CLMUL GHASH multiplication implementation
	 **********************************************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESASM_CLMULNI",
			    "Assembler AES using GCM with CLMUL GHASH implementation"),
	/* OpenSSL AES assembler with 4-bit assembler GHASH multiplication
	 * implementation *****************************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "X86", "AESASM_ASM",
			    "Assembler AES using GCM with 4-bit assembler GHASH implementation"),

	/* Now we move to the SHA-1 and SHA-2 implementations. OpenSSL has 3
	 * different functions which can contain assembler implementations:
	 *
	 * 1) sha1_block_data_order, used for SHA-1.
	 * 2) sha256_block_data_order, used for SHA-256 and related.
	 * 3) sha512_block_data_order, used for SHA-512 and related.
	 *
	 * Hardware accelerations are selected directly in the assembler
	 * implementations. For x86, the following are defined, in order of
	 * precedence:
	 * 1) SHA-NI implementation (if SHA bit is set in CPUID). Not available
	 *    for SHA-512 and related.
	 * 2) AVX2 implementation (if AVX2+BMI1+BMI2 bits are set in CPUID).
	 * 3) AVX implementation (if AVX and "Intel CPU" bits are set in CPUID).
	 * 4) SSSE3 implementation (if SSSE3 bit is set in CPUID). Not available
	 *    for SHA-512 and related.
	 * 5) Assembler implementation. This is the fallback implementation.
	 *
	 * Strictly speaking, there is also an XOP implementation for SHA-512,
	 * which uses the XOP instructions provided on a very small number of
	 * old AMD CPUs. We assume this implementation is never used.
	 *
	 * Source: crypto/sha/asm/
	 * Source: crypto/sha/asm/sha1-x86_64.pl
	 * Source: crypto/sha/asm/sha512-x86_64.pl
	 **********************************************************************/

	/* OpenSSL SHA-NI implementation **************************************/
	OPENSSL_IMPL_SHA("X86", "SHA_SHANI", "Intel SHA-NI implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "X86", "SSH_SHANI",
		       "SSH KDF using Intel SHA-NI implementation"),
	/* OpenSSL SHA AVX2 implementation ************************************/
	OPENSSL_IMPL_SHA("X86", "SHA_AVX2", "AVX2 SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "X86", "SSH_AVX2",
		       "SSH KDF using AVX2 SHA implementation"),
	/* OpenSSL SHA AVX implementation *************************************/
	OPENSSL_IMPL_SHA("X86", "SHA_AVX", "AVX SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "X86", "SSH_AVX",
		       "SSH KDF using AVX SHA implementation"),
	/* OpenSSL SHA SSSE3 implementation ***********************************/
	OPENSSL_IMPL_SHA("X86", "SHA_SSSE3", "SSSE3 SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "X86", "SSH_SSSE3",
		       "SSH KDF using SSSE3 SHA implementation"),
	/* OpenSSL SHA assembler implementation *******************************/
	OPENSSL_IMPL_SHA("X86", "SHA_ASM", "Assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "X86", "SSH_ASM",
		       "SSH KDF using assembler SHA implementation"),

	/* Finally, we come to SHA-3. OpenSSL has 4 different implementations
	 * for SHA-3, but only one of them is currently actually used. Still, we
	 * can imagine a kind of precedence for x86 as follows:
	 * 1) AVX512VL implementation (if AVX512VL bit is set in CPUID):
	 *    asm/keccak1600-avx512vl.pl.
	 * 2) AVX512 implementation (if AVX512 bit is set in CPUID):
	 *    asm/keccak1600-avx512.pl.
	 * 3) AVX2 implementation (if AVX2 bit is set in CPUID):
	 *    asm/keccak1600-avx2.pl.
	 * 4) Assembler implementation. This is the fallback implementation.
	 *
	 * However, currently only the plain assembler implementation is used.
	 * We still keep the existing definitions here for future compatibility.
	 *
	 * Source: crypto/sha/build.info
	 **********************************************************************/

	/* OpenSSL SHA3 AVX512VL implementation *********************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "X86", "SHA3_AVX512VL",
			    "AVX-512VL SHA-3 implementation"),
	/* OpenSSL SHA3 AVX512 implementation *********************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "X86", "SHA3_AVX512",
			    "AVX-512 SHA-3 implementation"),
	/* OpenSSL SHA3 AVX2 implementation ***********************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "X86", "SHA3_AVX2",
			    "AVX2 SHA-3 implementation"),
	/* OpenSSL SHA3 assembler implementation ******************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "X86", "SHA3_ASM",
			    "Assembler SHA-3 implementation"),

	/* ARM starts here. We won't repeat all the precedence rules. *********/

	/* HWAES_CAPABLE is set if ARMV8_AES bit is set. */
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "ARM64", "CE",
			    "ARMv8 Cryptographic Extension AES implementation"),
	/* BSAES_CAPABLE and VPAES_CAPABLE are both set if ARMV7_NEON bit is set.
	 * However, because of the precedence (see above), the bit sliced
	 * implementation is used first. Unfortunately, the acvpproxy name of
	 * this implementation is "VPAES", even though it is actually the BSAES
	 * implementation. This is reflected in the description.
	 **********************************************************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "ARM64", "VPAES",
			    "ARMv7 NEON bit sliced AES implementation"),
	/* The fallback implementation (see above), unfortunately named C even
	 * though it is implemented in plain assembler.
	 **********************************************************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "ARM64", "AES_C",
			    "Assembler AES implementation"),

	/* For AES GCM, there is no major differences with normal AES. The only
	 * difference is that, if loop unrolling and EOR3 are available,
	 * separate implementations are used. These have the highest precedence.
	 **********************************************************************/

	/* OpenSSL 3 GCM with (12 data chunks interleaved) loop unrolling and
	 * EOR3 implementation.
	 **********************************************************************/
	IMPLEMENTATION(openssl_gcm, "3_OpenSSL", "ARM64", "CE_GCM_UNROLL12_EOR3",
		       "ARMv8 Cryptographic Extension GCM using 12 data chunks interleaved loop unrolling and EOR3 implementation"),
	/* OpenSSL 3 GCM with (8 data chunks interleaved) loop unrolling and
	 * EOR3 implementation.
	 **********************************************************************/
	IMPLEMENTATION(openssl_gcm, "3_OpenSSL", "ARM64", "CE_GCM_UNROLL8_EOR3",
		       "ARMv8 Cryptographic Extension GCM using 8 data chunks interleaved loop unrolling and EOR3 implementation"),
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "ARM64", "CE_GCM",
			    "ARMv8 Cryptographic Extension GCM implementation"),
	/* Again, poorly named, this is actually a bit sliced implementation. */
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "ARM64", "VPAES_GCM",
			    "ARMv7 NEON bit sliced AES GCM implementation"),
	/* Again, poorly named, this is actually an assembler implementation. */
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "ARM64", "AES_C_GCM",
			    "Assembler AES GCM implementation"),

	/* For SHA-1 and SHA-2, the precedence on ARM platforms is as follows:
	 * 1) ARMv8 Cryptography Extension implementation (if CE is available).
	 * 2) ARMv7 NEON implementation (if NEON is available).
	 * 3) Assembler implementation. This is the fallback implementation.
	 *
	 * Source: crypto/sha/asm/sha1-armv4-large.pl
	 * Source: crypto/sha/asm/sha1-armv8.pl
	 * Source: crypto/sha/asm/sha256-armv4.pl
	 * Source: crypto/sha/asm/sha512-armv8.pl
	 **********************************************************************/
	/* OpenSSL ARMv8 CE Assembler implementation **************************/
	OPENSSL_IMPL_SHA("ARM64", "SHA_CE",
			 "ARMv8 Cryptographic Extension SHA implementation"),
	/* OpenSSL ARMv7 NEON Assembler implementation ************************/
	OPENSSL_IMPL_COMMON(openssl_neon, openssl_neon, "ARM64", "NEON",
			    "ARMv7 NEON SHA implementation"),
	/* OpenSSL ARM Assembler implementation *******************************/
	OPENSSL_IMPL_SHA("ARM64", "SHA_ASM", "Assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "ARM64", "SSH_ASM",
		       "SSH KDF using Assembler SHA implementation"),

	/* For SHA-3, there is either:
	 * a) crypto/sha/asm/keccak1600-armv4.pl for 32-bit ARM families.
	 * b) crypto/sha/asm/keccak1600-armv8.pl for 64-bit ARM families (i.e.
	 *    aarch64). This implementation uses the Cryptography Extension.
	 **********************************************************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "ARM64", "SHA3_CE",
			    "ARMv8 Cryptographic Extension SHA-3 implementation"),
	/* OpenSSL ARM Assembler implementation *******************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "ARM64", "SHA3_ASM",
			    "Assembler SHA-3 implementation"),

	/* s390x/IBM z starts here. We won't repeat all the precedence rules. */

	/* s390x provides PAI implementations for AES (CPACF). When available,
	 * they will be used. Otherwise, a plain assembler implementation is
	 * used. The following CPACF implementations are supported by OpenSSL:
	 * a) AES ECB and AES CBC (indicated by the km bits).
	 * b) AES OFB (indicated by the ko bits).
	 * c) AES CFB and CFB8 (indicated by the kmf bits).
	 * d) AES CTR (note: never used by OpenSSL as it was slower than sw).
	 * e) AES XTS (indicated by the km bits).
	 * f) AES GCM (indicated by the kma bits).
	 * g) AES CCM (indicated by the kmac bits).
	 *
	 * Source: include/crypto/aes_platform.h
	 * Source: crypto/aes/asm/aes-s390x.pl
	 * Source: https://www.openssl.org/docs/man3.0/man3/OPENSSL_s390xcap.html
	 **********************************************************************/

	/* OpenSSL s390x CPACF AES implementation *****************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "S390", "AES_CPACF",
			    "CPACF AES implementation"),
	/* OpenSSL s390x AES assembler implementation**************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "S390", "AESASM",
			    "Assembler AES implementation"),

	/* For AES GCM, there is again a precedence:
	 * 1) CPACF using kma instructions that implement AES GCM.
	 *    providers/implementations/ciphers/cipher_aes_gcm_hw_s390x.inc
	 * 2) AES assembler implementation with kimd that implements AES GHASH.
	 *    crypto/modes/asm/ghash-s390x.pl
	 * 3) AES assembler implementation with GHASH assembler implementation.
	 *    crypto/modes/asm/ghash-s390x.pl
	 *
	 * Source: https://www.openssl.org/docs/man3.0/man3/OPENSSL_s390xcap.html
	 **********************************************************************/

	/* OpenSSL s390x CPACF AES GCM implementation *************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "S390", "AESGCM_CPACF",
			    "CPACF AES GCM implementation"),
	/* OpenSSL s390x AES assembler implementation using CPACF GCM *********/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "S390", "AESGCM_ASM_CPACF",
			    "Assembler AES using GCM with CPACF GHASH implementation"),
	/* OpenSSL s390x AES assembler with 4-bit assembler GHASH multiplication
	 * implementation *****************************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "S390", "AESGCM_ASM_ASM",
			    "Assembler AES using GCM with 4-bit assembler GHASH implementation"),

	/* s390x provides PAI implementations for SHA-1, SHA-2, SHA-3, ECC, and
	 * ECDSA. When available, they will be used. Otherwise, a plain
	 * assembler implementation is used. The following CPACF implementations
	 * are supported by OpenSSL:
	 * a) SHA-1, SHA-256, SHA-512, SHA-3, and SHAKE (indicated by the kimd
	 *    bits).
	 * b) SHA-3 and SHAKE (indicated by the klmd bits).
	 * c) ECC point scalar multiplication (indicated by the pcc bits). Can
	 *    be used for key pair generation, shared secret computation, etc.
	 *    crypto/ec/ecp_s390x_nistp.c
	 *    crypto/ec/ecx_s390x.c
	 * d) ECDSA sign/verify implementations (indicated by the kdsa bits).
	 *    crypto/ec/ecp_s390x_nistp.c
	 *    crypto/ec/ecx_meth.c
	 *    providers/implementations/signature/eddsa_sig.c
	 *
	 * Note that OPENSSL_IMPL_SHA also includes the ECDH and ECDSA test
	 * definitions.
	 *
	 * Source: https://www.openssl.org/docs/man3.0/man3/OPENSSL_s390xcap.html
	 **********************************************************************/

	/* OpenSSL s390x CPACF SHA implementations ****************************/
	OPENSSL_IMPL_SHA("S390", "SHA_CPACF", "CPACF SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "S390", "SSH_CPACF",
		       "SSH KDF using CPACF SHA implementation"),
	/* OpenSSL s390x SHA assembler implementations ************************/
	OPENSSL_IMPL_SHA("S390", "SHA_ASM", "Assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "S390", "SSH_ASM",
		       "SSH KDF using assembler SHA implementation"),

	/* OpenSSL s390x CPACF SHA-3 implementations **************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "S390", "SHA3_CPACF",
			    "CPACF SHA-3 implementation"),
	/* OpenSSL s390x SHA-3 assembler implementations **********************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "S390", "SHA3_ASM",
			    "Assembler SHA-3 implementation"),

	/* POWER starts here. We won't repeat all the precedence rules. *******/

	/* OpenSSL POWER Assembler implementation *****************************
	 * Note: we may execute more ciphers than strictly provided by the ASM
	 * implementation, but we do not care
	 *
	 * crypto/aes/asm/aesp8-ppc.pl: This implementation uses the vcipher
	 * instruction set specified in the ISA 2.07 section 5.11.1, i.e. the
	 * PAI.
	 *
	 * That implementation seemingly is only used in
	 * providers/implementations/ciphers/cipher_aes_gcm_hw_ppc.inc
	 * referenced with static const PROV_GCM_HW aes_ppc_gcm. This is only
	 * used with PPC_AES_GCM_CAPABLE ? &aes_ppc_gcm : &aes_gcm.
	 *
	 * In turn, PPC_AES_GCM_CAPABLE is only set with:
	 * #   define PPC_AES_GCM_CAPABLE (OPENSSL_ppccap_P & PPC_MADD300)
	 *
	 * Yet, PPC_CRYPTO207 enables HWAES_CAPABLE which compiles the HWAES_*
	 * functions which point to the aes_p8* functions.
	 *
	 * VMX (setting PPC_CRYPTO207 in OpenSSL), however, refers to assembler
	 * implementation as the following is enabled:
	 * crypto/modes/asm/ghashp8-ppc.pl. This code does not use vcipher, but
	 * the other v... instructions which are just some math operations like
	 * Intel AVX to my interpretation.
	 *
	 * The SHA PAI implementation is provided with
	 * crypto/sha/asm/sha512p8-ppc.pl as it contains vashasigma*. This
	 * implementation is invoked from crypto/sha/sha_ppc.c with:
	 * OPENSSL_ppccap_P & PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) :
	 *         sha256_block_ppc(ctx, inp, len);
	 *
	 * and
	 * OPENSSL_ppccap_P & PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) :
	 *         sha512_block_ppc(ctx, inp, len);
	 *
	 * This means that for the SHA implementation, PPC_CRYPTO207 uses the
	 * PAI.
	 *
	 * Bottom line for our ACVP Proxy definitions:
	 *
	 * - AES_VMX and SSH_VMX refers to the PAA
	 *
	 * - SHA_VMX refers to the PAA
	 */
	/* OpenSSL POWER assembler implementation *****************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "POWER", "AESASM",
			    "Assembler AES implementation"),
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "POWER", "AESASM_ASM",
			    "Assembler AES using GCM with assembler GHASH implementation"),
	OPENSSL_IMPL_SHA("POWER", "SHA_ASM", "Assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "POWER", "SSH_ASM",
		       "SSH KDF using assembler SHA implementation"),
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "POWER", "SHA3_ASM",
			    "Assembler SHA-3 implementation"),

	/* OpenSSL POWER ISA (VMX) assembler implementation *******************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "POWER", "AES_ISA",
			    "ISA assembler AES implementation"),
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "POWER", "AES_ISA_ASM",
			    "ISA assembler AES using GCM with 4-bit assembler GHASH implementation"),
	OPENSSL_IMPL_SHA_POWER("POWER", "SHA_ISA",
			       "ISA assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "POWER", "SSH_ISA",
		       "SSH KDF using ISA assembler SHA implementation"),

	/* OpenSSL POWER Altivec assembler implementation *********************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "POWER", "AES_Altivec",
			    "Altivec assembler AES implementation"),
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "POWER", "AES_Altivec_ASM",
			    "Altivec assembler AES using GCM with 4-bit assembler GHASH implementation"),

	/* MIPS64 starts here. We won't repeat all the precedence rules. ******/

	/* MIPS64 Assembler implementation *************************************
	 * Note: we may execute more ciphers than strictly provided by the ASM
	 * implementation, but we do not care
	 *
	 * OpenSSL currently does not provide any accelerated implementations
	 * for MIPS. Of course, the assembly implementations are still provided
	 * as those are generally used as fall-back implementations.
	 *
	 * Therefore, we simply test assembly for all AES and SHA.
	 *
	 * For SHA-3, OpenSSL doesn't even provide a MIPS assembly
	 * implementation, so we test the C implementation (this implementation
	 * is only compiled if there is no assembly implementation).
	 *
	 * Source: crypto/aes/asm/aes-mips.pl
	 * Source: crypto/sha/asm/sha1-mips.pl
	 * Source: crypto/sha/asm/sha512-mips.pl
	 * Source: crypto/sha/keccak1600.c
	 */
	/* OpenSSL AES assembler implementation *******************************/
	OPENSSL_IMPL_COMMON(openssl_aes, openssl_3_aes, "MIPS64", "AESASM",
			    "Assembler AES implementation"),
	/* OpenSSL AES assembler with 4-bit assembler GHASH multiplication
	 * implementation *****************************************************/
	OPENSSL_IMPL_COMMON(openssl_gcm, openssl_gcm, "MIPS64", "AESASM_ASM",
			    "Assembler AES using GCM with 4-bit assembler GHASH implementation"),
	/* OpenSSL SHA assembler implementation *******************************/
	OPENSSL_IMPL_SHA("MIPS64", "SHA_ASM", "Assembler SHA implementation"),
	IMPLEMENTATION(openssl_ssh, "OpenSSL", "MIPS64", "SSH_ASM",
		       "SSH KDF using assembler SHA implementation"),
	/* OpenSSL SHA3 C implementation **************************************/
	OPENSSL_IMPL_COMMON(openssl_sha3, openssl_3_sha3, "MIPS64", "SHA3_C",
			    "Generic C SHA-3 implementation"),

};

ACVP_DEFINE_CONSTRUCTOR(openssl_register)
static void openssl_register(void)
{
	acvp_register_algo_map(openssl_algo_map, ARRAY_SIZE(openssl_algo_map));
}

ACVP_EXTENSION(openssl_algo_map)
