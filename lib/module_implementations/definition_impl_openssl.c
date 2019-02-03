/* OpenSSL module definition
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
#define OPENSSL_SHA(x)	GENERIC_SHA(x)
#define OPENSSL_HMAC(x)	GENERIC_HMAC(x)
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
	.noncelen = { DEF_ALG_ZERO_VALUE },				\
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
	.noncelen = { DEF_ALG_ZERO_VALUE, },				\
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
	.noncelen = { DEF_ALG_ZERO_VALUE, },				\
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
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	OPENSSL_RSA_KEYGEN_CAPS_COMMON
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

static const struct def_algo_rsa_siggen_caps openssl_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGGEN_CAPS_COMMON
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	OPENSSL_RSA_SIGGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_siggen openssl_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_siggen_caps),
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
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	OPENSSL_RSA_SIGVER_CAPS_COMMON,
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	OPENSSL_RSA_SIGVER_CAPS_COMMON,
} };

static const struct def_algo_rsa_sigver openssl_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = openssl_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(openssl_rsa_sigver_caps),
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
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
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
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
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

/**************************************************************************
 * ECDH Definitions
 **************************************************************************/
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

#define __OPENSSL_KAS_ECC(paramset)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC,					\
	.algo.kas_ecc = {						\
		DEF_PREREQS(openssl_rsa_prereqs),			\
		.kas_ecc_function = DEF_ALG_KAS_ECC_PARTIALVAL,		\
		.kas_ecc_schema = DEF_ALG_KAS_ECC_EPHEMERAL_UNIFIED,	\
		.kas_ecc_role = DEF_ALG_KAS_ECC_INITIATOR |		\
				DEF_ALG_KAS_ECC_RESPONDER,		\
		.kas_ecc_dh_type = DEF_ALG_KAS_ECC_NO_KDF_NO_KC,	\
		.type_info.nokdfnokc = paramset,			\
		},							\
	}

#define OPENSSL_KAS_ECC							\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ec),		\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ed),		\
	__OPENSSL_KAS_ECC(&openssl_kas_ecc_nokdfnokc_ee)

/**************************************************************************
 * FFC DH Definitions
 **************************************************************************/
static const struct def_algo_kas_ffc_nokdfnokc openssl_kas_ffc_nokdfnokc_fb = {
	.kas_ffc_paramset = DEF_ALG_KAS_FFC_FB,
	.hashalg = ACVP_SHA224
};

static const struct def_algo_kas_ffc_nokdfnokc openssl_kas_ffc_nokdfnokc_fc = {
	.kas_ffc_paramset = DEF_ALG_KAS_FFC_FC,
	.hashalg = ACVP_SHA256
};

#define __OPENSSL_KAS_FFC(paramset)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_FFC,					\
	.algo.kas_ffc = {						\
		DEF_PREREQS(openssl_rsa_prereqs),			\
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

	OPENSSL_CMAC_AES
};

static const struct def_algo openssl_gcm [] = {
	OPENSSL_AES_ECB,

	OPENSSL_AES_GCM,
	OPENSSL_AES_GCM_IIV,

	OPENSSL_DRBG_CTR
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

	OPENSSL_DRBG_HMAC,
	OPENSSL_DRBG_HASH,

	OPENSSL_RSA_KEYGEN,
	OPENSSL_RSA_SIGGEN,
	OPENSSL_RSA_SIGVER,

	OPENSSL_ECDSA_KEYGEN,
	OPENSSL_ECDSA_KEYVER,
	OPENSSL_ECDSA_SIGGEN,
	OPENSSL_ECDSA_SIGVER,

	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224, ACVP_SHA224),
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, ACVP_SHA256),
	OPENSSL_DSA_PQGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256, ACVP_SHA256),

	OPENSSL_DSA_PQGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160, ACVP_SHA1),
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
	OPENSSL_KAS_FFC,
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
		.impl_name = "TDES_C"
	}, {
	/* OpenSSL ACVP_NI implementation **************************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI"
	}, {
	/* OpenSSL ACVP_NI with AVX GHASH multiplication implementation ********/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_AVX"
	}, {
	/* OpenSSL ACVP_NI with CLMULNI GHASH multiplication implementation ****/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_CLMULNI"
	}, {
	/* OpenSSL ACVP_NI with assembler GHASH multiplication implementation **/
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESNI_ASM"

	}, {
	/* OpenSSL AES assembler implementation *******************************/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM"
	}, {
	/* OpenSSL AES assembler with AVX GHASH multiplication implementation */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_AVX"
	}, {
	/***********************************************************************
	 * OpenSSL AES assembler with CLMULNI GHASH multiplication
	 * implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_CLMULNI"
	}, {
	/***********************************************************************
	 * OpenSSL AES assembler with assembler GHASH multiplication
	 * implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "AESASM_ASM"

	}, {
	/* OpenSSL AES constant time SSSE3 and Bit Slice implementation *******/
		SET_IMPLEMENTATION(openssl_aes),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with AVX GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_AVX"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with CLMULNI GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_CLMULNI"
	}, {
	/***********************************************************************
	 * OpenSSL AES constant time SSSE3 and Bit Slice with assembler GHASH
	 * multiplication implementation
	 */
		SET_IMPLEMENTATION(openssl_gcm),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "BAES_CTASM_ASM"

	}, {
	/* OpenSSL SHA AVX2 implementation ************************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_AVX2"
	}, {
	/* OpenSSL SHA AVX implementation *************************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_AVX"
	}, {
	/* OpenSSL SHA SSSE3 implementation ***********************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_SSSE3"
	}, {
	/* OpenSSL SHA assembler implementation *******************************/
		SET_IMPLEMENTATION(openssl_sha),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA_ASM"
	}, {
	/* OpenSSL SHA3 AVX2 implementation ***********************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_AVX2"
	}, {
	/* OpenSSL SHA3 AVX512 implementation *********************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_AVX512"
	}, {
	/* OpenSSL SHA3 assembler implementation ******************************/
		SET_IMPLEMENTATION(openssl_sha3),
		.algo_name = "OpenSSL",
		.processor = "X86",
		.impl_name = "SHA3_ASM"
	},
};

ACVP_DEFINE_CONSTRUCTOR(openssl_register)
static void openssl_register(void)
{
	acvp_register_algo_map(openssl_algo_map, ARRAY_SIZE(openssl_algo_map));
}
