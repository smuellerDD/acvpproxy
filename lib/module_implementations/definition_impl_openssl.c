/* OpenSSL module definition
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

#include "definition.h"
#include "definition_impl_common.h"

/**************************************************************************
 * AES Definitions
 **************************************************************************/
static const struct def_algo_prereqs openssl_gcm_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define OPENSSL_AES_ECB		GENERIC_AES_ECB
#define OPENSSL_AES_CBC		GENERIC_AES_CBC
#define OPENSSL_AES_CTR		GENERIC_AES_CTR
#define OPENSSL_AES_KW		GENERIC_AES_KW
#define OPENSSL_AES_KWP		GENERIC_AES_KWP
#define OPENSSL_AES_XTS		GENERIC_AES_XTS
#define OPENSSL_AES_OFB		GENERIC_AES_OFB
#define OPENSSL_AES_CFB1	GENERIC_AES_CFB1
#define OPENSSL_AES_CFB8	GENERIC_AES_CFB8
#define OPENSSL_AES_CFB128	GENERIC_AES_CFB128
#define OPENSSL_AES_GMAC	GENERIC_AES_GMAC_821

#define OPENSSL_AES_GCM							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_GCM),					\
	.algo.sym.ptlen = { 128, 256, 120, 248 },			\
	.algo.sym.ivlen = { 96, 128 },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_EXTERNAL,			\
	.algo.sym.ivgenmode = DEF_ALG_SYM_IVGENMODE_821,		\
	.algo.sym.aadlen = { 128, 256, 120, DEF_ALG_ZERO_VALUE },	\
	.algo.sym.taglen = { 32, 64, 96, 104, 112, 120, 128 },		\
	.algo.sym.prereqvals = openssl_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(openssl_gcm_prereqs)	\
	}

/* IIV is only defined for encryption */
#define OPENSSL_AES_GCM_IIV						\
	{								\
	.type = DEF_ALG_TYPE_SYM,					\
	.algo.sym.algorithm = ACVP_GCM,					\
	.algo.sym.direction = DEF_ALG_SYM_DIRECTION_ENCRYPTION,		\
	.algo.sym.keylen = DEF_ALG_SYM_KEYLEN_128 |			\
			   DEF_ALG_SYM_KEYLEN_192 |			\
			   DEF_ALG_SYM_KEYLEN_256,			\
	.algo.sym.ptlen = { 128, 256, 120, 248 },			\
	.algo.sym.ivlen = { 96, },					\
	.algo.sym.ivgen = DEF_ALG_SYM_IVGEN_INTERNAL,			\
	.algo.sym.ivgenmode = DEF_ALG_SYM_IVGENMODE_821,		\
	.algo.sym.aadlen = { 64, 96 },					\
	.algo.sym.taglen = { 64, 96, 128 },				\
	.algo.sym.prereqvals = openssl_gcm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(openssl_gcm_prereqs)	\
	}

#define OPENSSL_AES_CCM							\
	{								\
	GENERIC_AES_ALGO_GEN(ACVP_CCM),					\
	.algo.sym.ptlen = { 256 },					\
	.algo.sym.ivlen = { 56, 64, 72, 80, 88, 96, 104, },		\
	.algo.sym.aadlen = { DEF_ALG_ZERO_VALUE, 256, 65536 },		\
	.algo.sym.taglen = { 32, 48, 64, 80, 96, 112, 128 },		\
	.algo.sym.prereqvals = generic_ccm_prereqs,			\
	.algo.sym.prereqvals_num = ARRAY_SIZE(generic_ccm_prereqs)	\
	}

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
	GENERIC_CMAC_AES((DEF_ALG_SYM_KEYLEN_128 | DEF_ALG_SYM_KEYLEN_192 | \
			 DEF_ALG_SYM_KEYLEN_256))

#define OPENSSL_CMAC_TDES						\
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

/**************************************************************************
 * DRBG Definitions
 **************************************************************************/
static const struct def_algo_prereqs aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
};

#define OPENSSL_DRBG_CAPS_AES128					\
	.mode = ACVP_AES128,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 512

#define OPENSSL_DRBG_CAPS_AES128_DF					\
	{								\
	OPENSSL_DRBG_CAPS_AES128,					\
	.entropyinputlen = { 128, },					\
	.noncelen = { 64 },						\
	.df = true							\
	}

#define OPENSSL_DRBG_CAPS_AES128_NODF					\
	{								\
	OPENSSL_DRBG_CAPS_AES128,					\
	.entropyinputlen = { 256, },					\
	.noncelen = { 64 },						\
	.df = false							\
	}

#define OPENSSL_DRBG_CAPS_AES192					\
	.mode = ACVP_AES192,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 1024

#define OPENSSL_DRBG_CAPS_AES192_DF					\
	{								\
	OPENSSL_DRBG_CAPS_AES192,					\
	.entropyinputlen = { 192, },					\
	.noncelen = { 128, },						\
	.df = true							\
	}

#define OPENSSL_DRBG_CAPS_AES192_NODF					\
	{								\
	OPENSSL_DRBG_CAPS_AES192,					\
	.entropyinputlen = { 320, },					\
	.noncelen = { 96, },						\
	.df = false							\
	}

#define OPENSSL_DRBG_CAPS_AES256					\
	.mode = ACVP_AES256,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 512

#define OPENSSL_DRBG_CAPS_AES256_DF					\
	{								\
	OPENSSL_DRBG_CAPS_AES256,					\
	.entropyinputlen = { 256, },					\
	.noncelen = { 128, },						\
	.df = true							\
	}

#define OPENSSL_DRBG_CAPS_AES256_NODF					\
	{								\
	OPENSSL_DRBG_CAPS_AES256,					\
	.entropyinputlen = { 384, },					\
	.noncelen = { 128, },						\
	.df = false							\
	}

#define OPENSSL_DRBG_CTR						\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "ctrDRBG",				\
			DEF_PREREQS(aes_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
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

#define OPENSSL_DRBG_CAPS_SHA1						\
	{								\
	.mode = ACVP_SHA1,						\
	.entropyinputlen = { 160, },					\
	.noncelen = { 160, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 320,						\
	}

#define OPENSSL_DRBG_CAPS_SHA224					\
	{								\
	.mode = ACVP_SHA224,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 224,						\
	}

#define OPENSSL_DRBG_CAPS_SHA256					\
	{								\
	.mode = ACVP_SHA256,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 1024,					\
	}

#define OPENSSL_DRBG_CAPS_SHA384					\
	{								\
	.mode = ACVP_SHA384,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 384,						\
	}

#define OPENSSL_DRBG_CAPS_SHA512					\
	{								\
	.mode = ACVP_SHA512,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 2048,					\
	}

#define OPENSSL_DRBG_HMAC						\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
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

#define OPENSSL_DRBG_HASH						\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
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

#define OPENSSL_RSA_KEYGEN_CAPS_COMMON					\
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_C2,

static const struct def_algo_rsa_keygen_caps openssl_rsa_keygen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_KEYGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_keygen openssl_rsa_keygen = {
	.rsa_randpq = DEF_ALG_RSA_PQ_B33_PRIMES,
	.capabilities = openssl_rsa_keygen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_keygen_caps),
};

static const struct def_algo_rsa_keygen_gen openssl_rsa_keygen_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_STANDARD,
};

#define OPENSSL_RSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_KEYGEN,		\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.gen_info.keygen = &openssl_rsa_keygen_gen,	\
			.algspecs.keygen = &openssl_rsa_keygen,		\
			.algspecs_num = 1,				\
			}						\
		}							\
	}

#define OPENSSL_RSA_SIGGEN_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512

#define OPENSSL_RSA_SIGGEN_CAPS_X931					\
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 |		\
		   ACVP_SHA512

static const struct def_algo_rsa_siggen_caps openssl_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_siggen_caps openssl_rsa_siggen_caps_pss[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
} };

#define OPENSSL_RSA_SIGGEN_CAPS_X931					\
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 |		\
		   ACVP_SHA512

static const struct def_algo_rsa_siggen_caps openssl_rsa_siggen_caps_x931[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGGEN_CAPS_X931
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGGEN_CAPS_X931
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_SIGGEN_CAPS_X931
} };

static const struct def_algo_rsa_siggen openssl_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_siggen_caps_pss,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps_pss),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_ANSIX931,
	.capabilities = openssl_rsa_siggen_caps_x931,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps_x931),
} };

#define OPENSSL_RSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGGEN,		\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.algspecs.siggen = openssl_rsa_siggen,		\
			.algspecs_num = ARRAY_SIZE(openssl_rsa_siggen),	\
			}						\
		}							\
	}

#define OPENSSL_RSA_SIGVER_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512

static const struct def_algo_rsa_sigver_caps openssl_rsa_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
} };

#define OPENSSL_RSA_SIGVER_CAPS_COMMON_X931				\
	.hashalg = ACVP_SHA1 | ACVP_SHA256 | ACVP_SHA384 |		\
		   ACVP_SHA512

static const struct def_algo_rsa_sigver_caps openssl_rsa_sigver_caps_x931[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_1024,
	OPENSSL_RSA_SIGVER_CAPS_COMMON_X931,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGVER_CAPS_COMMON_X931,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGVER_CAPS_COMMON_X931,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	OPENSSL_RSA_SIGVER_CAPS_COMMON_X931,
} };

static const struct def_algo_rsa_sigver openssl_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = openssl_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_ANSIX931,
	.capabilities = openssl_rsa_sigver_caps_x931,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps_x931),
} };

static const struct def_algo_rsa_sigver_gen openssl_rsa_sigver_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
};

#define OPENSSL_RSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGVER,		\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.gen_info.sigver = &openssl_rsa_sigver_gen,	\
			.algspecs.sigver = openssl_rsa_sigver,		\
			.algspecs_num = ARRAY_SIZE(openssl_rsa_sigver),	\
			}						\
		}							\
	}

/**************************************************************************
 * ECDSA Definitions
 **************************************************************************/

#define OPENSSL_ECDSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYGEN,	\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			.secretgenerationmode = DEF_ALG_ECDSA_TESTING_CANDIDATES \
			}						\
		}							\
	}

#define OPENSSL_ECDSA_KEYVER						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYVER,	\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			}						\
		}							\
	}

#define OPENSSL_ECDSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGGEN,	\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.curve = ACVP_NISTP224 | ACVP_NISTP256 | 	\
				 ACVP_NISTP384 | ACVP_NISTP521,		\
			.hashalg = ACVP_SHA224 | ACVP_SHA256 |		\
				   ACVP_SHA384 | ACVP_SHA512,		\
			}						\
		}							\
	}

#define OPENSSL_ECDSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGVER,	\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.curve = ACVP_NISTP224 | ACVP_NISTP256 |	\
				 ACVP_NISTP384 | ACVP_NISTP521,		\
			.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | \
				   ACVP_SHA384 | ACVP_SHA512,		\
			}						\
		}							\
	}

/**************************************************************************
 * DSA Definitions
 **************************************************************************/
#define OPENSSL_DSA_PQG_COMMON(x, L, N, hashes)				\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = x,					\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(openssl_rsa_prereqs),		\
			.dsa_pq_gen_method = DEF_ALG_DSA_PROBABLE_PQ_GEN, \
			.dsa_g_gen_method = DEF_ALG_DSA_UNVERIFIABLE_G_GEN, \
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define OPENSSL_DSA_PQGGEN(L, N, hashes)				\
		OPENSSL_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGGEN, L, N, hashes)
#define OPENSSL_DSA_PQGVER(L, N, hashes)				\
		OPENSSL_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGVER, L, N, hashes)

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
 * ECDH Definitions
 **************************************************************************/
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

/**************************************************************************
 * SP800-56A REV3
 **************************************************************************/
#define OPENSSL_KAS_ECC_SSC_R3						\
	GENERIC_KAS_ECC_SSC_R3(ACVP_NISTP224 | ACVP_NISTP256 |		\
		       	       ACVP_NISTP384 | ACVP_NISTP521)

#define OPENSSL_KAS_FFC_SSC_R3						\
	GENERIC_KAS_FFC_SSC_R3(ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |	\
			       ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |	\
			       ACVP_DH_MODP_8192 | ACVP_DH_FFDHE_2048 |	\
			       ACVP_DH_FFDHE_3072 | ACVP_DH_FFDHE_4096 |\
			       ACVP_DH_FFDHE_6144 | ACVP_DH_FFDHE_8192)

/**************************************************************************
 * TLS Definitions
 **************************************************************************/
static const struct def_algo_prereqs openssl_kdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define OPENSSL_KDF							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(openssl_kdf_prereqs),			\
		.tls_version = DEF_ALG_KDF_TLS_1_0_1_1 |		\
			       DEF_ALG_KDF_TLS_1_2,			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384			\
		}							\
	}

#define OPENSSL_TLS13_KDF						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS13,					\
	.algo.kdf_tls13 = {						\
		DEF_PREREQS(openssl_kdf_prereqs),			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512,	\
		.running_mode = DEF_ALG_KDF_TLS13_MODE_DHE		\
		}							\
	}

#define OPENSSL_HKDF							\
	{								\
	.type = DEF_ALG_TYPE_HKDF,					\
	.algo.hkdf = {							\
		DEF_PREREQS(openssl_kdf_prereqs),			\
		.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |	\
				   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,	\
		.fixed_info_pattern_type = {				\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO },\
		.cipher_spec = {					\
			.macalg = ACVP_SHA224 | ACVP_SHA256 |		\
				  ACVP_SHA384 | ACVP_SHA512,		\
			DEF_ALG_DOMAIN(.z, 224, 65336, 8),		\
			.l = 2048,					\
			}						\
		}							\
	}

/**************************************************************************
 * SSH Definitions
 **************************************************************************/
static const struct def_algo_prereqs openssl_kdf_aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs openssl_kdf_tdes_prereqs[] = {
	{
		.algorithm = "TDES",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define OPENSSL_KDF_AES							\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(openssl_kdf_aes_prereqs),			\
		.cipher = ACVP_AES128 | ACVP_AES192 | ACVP_AES256,	\
		.hashalg = ACVP_SHA1 | ACVP_SHA256 |			\
			   ACVP_SHA384 | ACVP_SHA512			\
		}							\
	}

#define OPENSSL_KDF_TDES						\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(openssl_kdf_tdes_prereqs),			\
		.cipher = ACVP_TDES,					\
		.hashalg = ACVP_SHA1 | ACVP_SHA256 |			\
			   ACVP_SHA384 | ACVP_SHA512			\
		}							\
	}

#define OPENSSL_KDF_SSH							\
	OPENSSL_KDF_AES,						\
	OPENSSL_KDF_TDES

/**************************************************************************
 * SP800-132 PBKDF Definitions
 **************************************************************************/
#define OPENSSL_PBKDF(x)	GENERIC_PBKDF(x)

/**************************************************************************
 * SP800-108 KDF Definitions
 **************************************************************************/
static const struct def_algo_prereqs openssl_kbkdf_hmac_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs openssl_kbkdf_cmac_prereqs[] = {
	{
		.algorithm = "TDES",
		.valvalue = "same"
	},
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "CMAC",
		.valvalue = "same"
	},
};

/*
 * KDF supports output lengths which are multiple of bytes - we support
 * any .supported_lengths, except for the Feedback mode which must be at least
 * of the size of the message digest.
 */
#define OPENSSL_KBKDF_CMAC(kdf_type, ctr_loc, sym_alg)			\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(openssl_kbkdf_cmac_prereqs),		\
		.kdf_108_type = kdf_type,				\
		.macalg = sym_alg,					\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = true,				\
		.requires_empty_iv = false				\
		}							\
	}

#define OPENSSL_KBKDF_CMAC_AES						\
	OPENSSL_KBKDF_CMAC(DEF_ALG_KDF_108_COUNTER,			\
			   DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			   ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |	\
			   ACVP_CMAC_AES256),				\
	OPENSSL_KBKDF_CMAC(DEF_ALG_KDF_108_FEEDBACK,			\
			   DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			   ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |	\
			   ACVP_CMAC_AES256)

#define OPENSSL_KBKDF_CMAC_TDES						\
	OPENSSL_KBKDF_CMAC(DEF_ALG_KDF_108_COUNTER,			\
			   DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			   ACVP_CMAC_TDES),				\
	OPENSSL_KBKDF_CMAC(DEF_ALG_KDF_108_FEEDBACK,			\
			   DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,\
			   ACVP_CMAC_TDES)

#define OPENSSL_KBKDF_HMAC_DEF(kdf_type, ctr_loc)			\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(openssl_kbkdf_hmac_prereqs),		\
		.kdf_108_type = kdf_type,				\
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |		\
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |	\
			  ACVP_HMACSHA2_512,				\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = true				\
		}							\
	}

#define OPENSSL_KBKDF_HMAC						\
	OPENSSL_KBKDF_HMAC_DEF(DEF_ALG_KDF_108_COUNTER,			\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	OPENSSL_KBKDF_HMAC_DEF(DEF_ALG_KDF_108_FEEDBACK,		\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA)

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
	OPENSSL_DRBG_CTR,
};

static const struct def_algo openssl_gcm [] = {
	OPENSSL_AES_GCM,
	//zero length data not supported by OpenSSL
	//OPENSSL_AES_GMAC,
	OPENSSL_AES_GCM_IIV,
};

static const struct def_algo openssl_ffcdh [] = {
	//SP800-56A rev 1 is not supported any more (arbitrary primes are
	//rejected)
	//OPENSSL_KAS_FFC,
	OPENSSL_KAS_FFC_SSC_R3,
	OPENSSL_SAFEPRIMES,
};

static const struct def_algo openssl_sha [] = {
	OPENSSL_SHA(ACVP_SHA1),
	OPENSSL_SHA(ACVP_SHA224),
	OPENSSL_SHA(ACVP_SHA256),
	OPENSSL_SHA(ACVP_SHA384),
	OPENSSL_SHA(ACVP_SHA512),

	OPENSSL_HMAC(ACVP_HMACSHA1),
	OPENSSL_HMAC(ACVP_HMACSHA2_224),
	OPENSSL_HMAC(ACVP_HMACSHA2_256),
	OPENSSL_HMAC(ACVP_HMACSHA2_384),
	OPENSSL_HMAC(ACVP_HMACSHA2_512),

	OPENSSL_RSA_KEYGEN,
	OPENSSL_RSA_SIGGEN,
	OPENSSL_RSA_SIGVER,

	OPENSSL_ECDSA_KEYGEN,
	OPENSSL_ECDSA_KEYVER,
	OPENSSL_ECDSA_SIGGEN,
	OPENSSL_ECDSA_SIGVER,

	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,
			   ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),

	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),

	/* DSA_generate_key */
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),

	//TODO OpenSSL SLES does not have 1024 bits, RHEL has it
	//OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160, ACVP_SHA1),
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224, ACVP_SHA224),
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, ACVP_SHA256),
	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256, ACVP_SHA256),

	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224),
	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256),
	OPENSSL_DSA_KEYGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256),

	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,
			   ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),
	OPENSSL_DSA_SIGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),

	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	OPENSSL_DSA_SIGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),

	OPENSSL_KDF,
	OPENSSL_KAS_ECC,
	OPENSSL_KAS_ECC_CDH,
	OPENSSL_KAS_ECC_SSC_R3,

	OPENSSL_PBKDF(ACVP_SHA1 |
		      ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),
};

static const struct def_algo openssl_ssh [] = {
	OPENSSL_TDES_ECB,
	OPENSSL_AES_ECB,
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
};

static const struct def_algo openssl_10x_drbg [] = {
	/* DRBG in crypto/fips/ */
	OPENSSL_DRBG_CTR,
	OPENSSL_DRBG_HMAC,
	OPENSSL_DRBG_HASH,
};

static const struct def_algo openssl_kbkdf [] = {
	OPENSSL_KBKDF_HMAC,
	OPENSSL_KBKDF_CMAC_AES,
	OPENSSL_KBKDF_CMAC_TDES,
};

static const struct def_algo openssl_neon [] = {
	OPENSSL_SHA(ACVP_SHA256),
	OPENSSL_HMAC(ACVP_HMACSHA2_256),
};

static const struct def_algo openssl_tls13 [] = {
	//OPENSSL_TLS13_KDF,
	OPENSSL_HKDF
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map openssl_algo_map [] = {
	{
	/* OpenSSL TDES C implementation **************************************/
		SET_IMPLEMENTATION(openssl_tdes),
		.algo_name = "OpenSSL",
		.processor = "",
		.impl_name = "TDES_C",
		.impl_description = "Generic C non-optimized TDES implementation"
	}, {
	/* OpenSSL KBKDF implementation **********************/
		SET_IMPLEMENTATION(openssl_kbkdf),
		.algo_name = "OpenSSL",
		.processor = "",
		.impl_name = "KBKDF",
		.impl_description = "Generic C non-optimized KBKDF implementation"
	}, {
	/* OpenSSL TLS 1.3 implementation **********************/
		SET_IMPLEMENTATION(openssl_tls13),
		.algo_name = "OpenSSL",
		.processor = "",
		.impl_name = "TLS v1.3",
		.impl_description = "TLS v1.3 implementation"
	}, {
	/* OpenSSL AESNI implementation ***************************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI",
		.impl_description = "Intel AES-NI AES implementation"
	}, {
	/* OpenSSL AESNI with AVX GHASH multiplication implementation *********/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_AVX",
		.impl_description = "Intel AES-NI AES using GCM with AVX GHASH  implementation"
	}, {
	/* OpenSSL AESNI with CLMULNI GHASH multiplication implementation *****/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_CLMULNI",
		.impl_description = "Intel AES-NI AES using GCM with Intel CLMULNI  implementation"
	}, {
	/* OpenSSL AESNI with assembler GHASH multiplication implementation ***/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_ASM",
		.impl_description = "Intel AES-NI AES using assembler block mode implementation"

	}, {
	/* OpenSSL AES assembler implementation *******************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM",
		.impl_description = "Assembler AES implementation"
	}, {
	/* OpenSSL AES assembler with AVX GHASH multiplication implementation */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_AVX",
		.impl_description = "Assembler AES using GCM with AVX GHASH implementation"
	}, {
	/***********************************************************************
	 * OpenSSL AES assembler with CLMULNI GHASH multiplication
	 * implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_CLMULNI",
		.impl_description = "Assembler AES using GCM with Intel CLMULNI  implementation"
	}, {
	/***********************************************************************
	 * OpenSSL AES assembler with assembler GHASH multiplication
	 * implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_ASM",
		.impl_description = "Assembler AES using GCM with assembler GHASH implementation"

	}, {
	/* OpenSSL AES constant time SSSE3 and Bit Slice implementation *******/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM",
		.impl_description = "Constant-time bit slice AES implementation"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with AVX GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_AVX",
		.impl_description = "Constant-time bit slice AES using GCM with AVX GHASH implementation"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with CLMULNI GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_CLMULNI",
		.impl_description = "Constant-time bit slice AES using GCM with Intel CLMULNI implementation"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with assembler GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_ASM",
		.impl_description = "Constant-time bit slice AES using GCM with assembler GHASH implementation"

	}, {
	/* OpenSSL SHA AVX2 implementation ************************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_AVX2",
		.impl_description = "AVX2 SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SSH_AVX2",
		.impl_description = "SSH KDF using AVX2 SHA implementation"
	}, {
	/* OpenSSL SHA AVX implementation *************************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_AVX",
		.impl_description = "AVX SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SSH_AVX",
		.impl_description = "SSH KDF using AVX SHA implementation"
	}, {
	/* OpenSSL SHA SSSE3 implementation ***********************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_SSSE3",
		.impl_description = "SSSE3 SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SSH_SSSE3",
		.impl_description = "SSH KDF using SSSE3 SHA implementation"
	}, {
	/* OpenSSL SHA assembler implementation *******************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_ASM",
		.impl_description = "Assembler SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SSH_ASM",
		.impl_description = "SSH KDF using assembler SHA implementation"
	}, {
	/* OpenSSL SHA3 AVX2 implementation ***********************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_AVX2",
		.impl_description = "AVX2 SHA-3 implementation"
	}, {
	/* OpenSSL SHA3 AVX512 implementation *********************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_AVX512",
		.impl_description = "Intel AVX-512 SHA-3 implementation"
	}, {
	/* OpenSSL SHA3 assembler implementation ******************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_ASM",
		.impl_description = "Assembler SHA-3 implementation"
	}, {
	/* OpenSSL FFC DH implementation **************************************/
		SET_IMPLEMENTATION(openssl_ffcdh),
		.algo_name = "OpenSSL",
		.processor = "",
		.impl_name = "FFC_DH",
		.impl_description = "Generic C non-optimized DH implementation"
	}, {

	/*
	 * OpenSSL 1.0.x upstream DRBG implementation that may have been
	 * forward-ported to 1.1.x (e.g. on RHEL8)
	 * The different instances relate to the different implementations of
	 * the underlying cipher
	 **********************************************************************/
		SET_IMPLEMENTATION(openssl_10x_drbg),
		.algo_name = "OpenSSL",
		.processor = "",
		.impl_name = "DRBG_10X",
		.impl_description = "Generic DRBG implementation with all types of DRBG"
	}, {

	/* crypto/evp/e_aes.c module:

	Definition of defines for __aarch64__ (lines 2552-2569) nad aes_init_key
	(lines 2603-2706) sets encrypt/decrypt key, encrypt/decrypt and
	cbc_encrypt functions depending on mask:

	a) HWAES_set_decrypt_key, HWAES_decrypt, HWAES_cbc_encrypt,
	HWAES_set_encrypt_key, HWAES_ctr32_encrypt_blocks for HWAES_CAPABLE

	b) AES_set_decrypt_key, AES_decrypt, bsaes_cbc_encrypt, AES_encrypt,
	bsaes_ctr32_encrypt_blocks for BSAES_CAPABLE (not compiled)

	c) vpaes_set_decrypt_key, vpaes_decrypt, vpaes_cbc_encrypt,
	vpaes_set_encrypt_key, vpaes_encrypt for VPAES_CAPABLE

	d) AES_set_decrypt_key, AES_decrypt, AES_cbc_encrypt,
	AES_set_encrypt_key, AES_encrypt, AES_ctr32_encrypt otherwise.


	So, for ARV8_AES executes a) (e.g. aes_v8_encrypt, defined in
	aesv8-armx.pl), for ARVV7_NEON c) (e.g. vpaes_encrypt, defined in
	vpaes-armv8.pl) and for capmask with those bits off d) (e.g. AES_encrypt).
	**********************************************************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "AES_C",
		.impl_description = "Generic C AES implementation"
	}, {
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "AES_C_GCM",
		.impl_description = "Generic C AES GCM implementation"
	}, {

	/* OpenSSL ARM64v8 Assembler implementation ***************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "SHA_ASM",
		.impl_description = "Assembler SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "SSH_ASM",
		.impl_description = "SSH KDF using Assembler SHA implementation"
	}, {
	/* OpenSSL ARM64v8 SHA3 assembler implementation **********************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "SHA3_ASM",
		.impl_description = "Assembler SHA-3 implementation"
	}, {
	/* OpenSSL ARM NEON Assembler implementation **************************/
		SET_IMPLEMENTATION(openssl_neon),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "NEON",
		.impl_description = "NEON Assembler SHA implementation"
	}, {
	/* OpenSSL ARM64v8 AES crypto extension *******************************
	 * Note: we may execute more ciphers than strictly provided by the CE
	 * implementation, but we do not care
	 */
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "CE",
		.impl_description = "ARM Cryptographic Extension AES implementation"
	}, {
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "CE_GCM",
		.impl_description = "ARM Cryptographic Extension GCM implementation"
	}, {
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "SHA_CE",
		.impl_description = "ARM Cryptographic Extension SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "SHA3_CE",
		.impl_description = "ARM Cryptographic Extension SHA-3 implementation"
	}, {

	/* OpenSSL ARM64v8 NEON bit slicing implementation ********************
	 * Note: we may execute more ciphers than strictly provided by the NEON
	 * implementation, but we do not care
	 */
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "VPAES",
		.impl_description = "ARM NEON bit slicing AES implementation"
	}, {
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "ARM64",
		.impl_name = "VPAES_GCM",
		.impl_description = "ARM NEON bit slicing AES using GCM implementation"
	}, {
	/* OpenSSL S390x Assembler implementation *****************************
	 * Note: we may execute more ciphers than strictly provided by the ASM
	 * implementation, but we do not care
	 */
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "S390",
		.impl_name = "SHA_ASM",
		.impl_description = "Assembler SHA implementation"
	}, {
		SET_IMPLEMENTATION(openssl_ssh),
		.algo_name = "OpenSSL",
		.processor = "S390",
		.impl_name = "SSH_ASM",
		.impl_description = "SSH KDF using Assembler SHA implementation"
	}, {
	/* OpenSSL S390x SHA3 assembler implementation ************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "S390",
		.impl_name = "SHA3_ASM",
		.impl_description = "Assembler SHA-3 implementation"
	}, {
	/* OpenSSL S390x assembler implementation *****************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "S390",
		.impl_name = "AESASM",
		.impl_description = "Assembler AES implementation"
	}, {
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "S390",
		.impl_name = "AESASM_ASM",
		.impl_description = "Assembler AES using GCM with assembler GHASH implementation"

	},
};

ACVP_DEFINE_CONSTRUCTOR(openssl_register)
static void openssl_register(void)
{
	acvp_register_algo_map(openssl_algo_map, ARRAY_SIZE(openssl_algo_map));
}

ACVP_EXTENSION(openssl_algo_map)
