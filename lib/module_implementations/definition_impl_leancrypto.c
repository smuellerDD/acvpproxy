/* leancrypto module definition
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
 * EDDSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs lc_eddsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};


#define LC_EDDSA_KEYGEN							\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_KEYGEN,	\
			DEF_PREREQS(lc_eddsa_prereqs),			\
			.curve = ACVP_ED25519,				\
			}						\
		}							\
	}

#define LC_EDDSA_SIGGEN							\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGGEN,	\
			DEF_PREREQS(lc_eddsa_prereqs),			\
			.curve = ACVP_ED25519,				\
			.eddsa_pure = DEF_ALG_EDDSA_PURE_SUPPORTED,	\
			.eddsa_prehash = DEF_ALG_EDDSA_PREHASH_SUPPORTED,\
			.context_length = { DEF_ALG_ZERO_VALUE },	\
			}						\
		}							\
	}

#define LC_EDDSA_SIGVER							\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGVER,	\
			DEF_PREREQS(lc_eddsa_prereqs),			\
			.curve = ACVP_ED25519,				\
			.eddsa_pure = DEF_ALG_EDDSA_PURE_SUPPORTED,	\
			.eddsa_prehash = DEF_ALG_EDDSA_PREHASH_SUPPORTED,\
			.context_length = { DEF_ALG_ZERO_VALUE },	\
			}						\
		}							\
	}

/**************************************************************************
 * ML-DSA Definitions
 **************************************************************************/
static const struct def_algo_ml_dsa_caps ml_dsa_keygen_full_capabilities[] = { {
	.parameter_set = DEF_ALG_ML_DSA_44 |
			 DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
} };

static const struct def_algo_ml_dsa_caps ml_dsa_sig_full_capabilities_pure[] = { {
	.parameter_set = DEF_ALG_ML_DSA_44 |
			 DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
} };

static const struct def_algo_ml_dsa_caps ml_dsa_sig_full_capabilities_prehash[] = { {
	.parameter_set = DEF_ALG_ML_DSA_44 |
			 DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
	.hashalg = ACVP_SHA3_512 | ACVP_SHA512 | ACVP_SHAKE256,
} };

#define LC_ML_DSA_KEYGEN_FULL						\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_KEYGEN,	\
			.capabilities.keygen = ml_dsa_keygen_full_capabilities,\
			.capabilities_num = ARRAY_SIZE(ml_dsa_keygen_full_capabilities),\
			}						\
		}							\
	}

#define LC_ML_DSA_SIGGEN_TYPE(m)					\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGGEN,	\
			.capabilities.siggen = m,			\
			.capabilities_num = ARRAY_SIZE(m),		\
			.deterministic = DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC |\
					 DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC,\
			.interface = DEF_ALG_ML_DSA_INTERFACE_EXTERNAL |\
				     DEF_ALG_ML_DSA_INTERFACE_INTERNAL, \
			.external_mu = DEF_ALG_ML_DSA_EXTERNAL_MU |	\
				       DEF_ALG_ML_DSA_INTERNAL_MU,	\
			}						\
		}							\
	}

#define LC_ML_DSA_SIGVER_TYPE(m)					\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_SIGVER,	\
			.capabilities.sigver = m,			\
			.capabilities_num = ARRAY_SIZE(m),		\
			.interface = DEF_ALG_ML_DSA_INTERFACE_EXTERNAL |\
				     DEF_ALG_ML_DSA_INTERFACE_INTERNAL, \
			.external_mu = DEF_ALG_ML_DSA_EXTERNAL_MU |	\
				       DEF_ALG_ML_DSA_INTERNAL_MU,	\
			}						\
		}							\
	}

#define LC_ML_DSA_SIGGEN_FULL						\
	LC_ML_DSA_SIGGEN_TYPE(ml_dsa_sig_full_capabilities_pure),	\
	LC_ML_DSA_SIGGEN_TYPE(ml_dsa_sig_full_capabilities_prehash)

#define LC_ML_DSA_SIGVER_FULL						\
	LC_ML_DSA_SIGVER_TYPE(ml_dsa_sig_full_capabilities_pure),	\
	LC_ML_DSA_SIGVER_TYPE(ml_dsa_sig_full_capabilities_prehash)

static const struct def_algo_ml_dsa_caps ml_dsa_keygen_strong_capabilities[] = { {
	.parameter_set = DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
} };

static const struct def_algo_ml_dsa_caps ml_dsa_sig_strong_capabilities_pure[] = { {
	.parameter_set = DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
} };

static const struct def_algo_ml_dsa_caps ml_dsa_sig_strong_capabilities_prehash[] = { {
	.parameter_set = DEF_ALG_ML_DSA_65 |
			 DEF_ALG_ML_DSA_87,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
	.hashalg = ACVP_SHA3_512 | ACVP_SHA512 | ACVP_SHAKE256,
} };

#define LC_ML_DSA_KEYGEN_STRONG						\
	{								\
	.type = DEF_ALG_TYPE_ML_DSA,					\
	.algo = {							\
		.ml_dsa = {						\
			.ml_dsa_mode = DEF_ALG_ML_DSA_MODE_KEYGEN,	\
			.capabilities.keygen = ml_dsa_keygen_strong_capabilities,\
			.capabilities_num = ARRAY_SIZE(ml_dsa_keygen_strong_capabilities),\
			}						\
		}							\
	}

#define LC_ML_DSA_SIGGEN_STRONG						\
	LC_ML_DSA_SIGGEN_TYPE(ml_dsa_sig_strong_capabilities_pure),	\
	LC_ML_DSA_SIGGEN_TYPE(ml_dsa_sig_strong_capabilities_prehash)

#define LC_ML_DSA_SIGVER_STRONG						\
	LC_ML_DSA_SIGVER_TYPE(ml_dsa_sig_strong_capabilities_pure),	\
	LC_ML_DSA_SIGVER_TYPE(ml_dsa_sig_strong_capabilities_prehash)

/**************************************************************************
 * ML-KEM Definitions
 **************************************************************************/

#define LC_ML_KEM_ALGO_SET_FULL						\
	(DEF_ALG_ML_KEM_512 | DEF_ALG_ML_KEM_768 | DEF_ALG_ML_KEM_1024)

#define LC_ML_KEM_KEYGEN_FULL						\
	GENERIC_ML_KEM_KEYGEN(LC_ML_KEM_ALGO_SET_FULL)

#define LC_ML_KEM_ENCAPDECAP_FULL					\
	GENERIC_ML_KEM_ENCAPDECAP(LC_ML_KEM_ALGO_SET_FULL)

#define LC_ML_KEM_ALGO_SET_STRONG					\
	(DEF_ALG_ML_KEM_768 | DEF_ALG_ML_KEM_1024)

#define LC_ML_KEM_KEYGEN_STRONG						\
	GENERIC_ML_KEM_KEYGEN(LC_ML_KEM_ALGO_SET_STRONG)

#define LC_ML_KEM_ENCAPDECAP_STRONG					\
	GENERIC_ML_KEM_ENCAPDECAP(LC_ML_KEM_ALGO_SET_STRONG)

/**************************************************************************
 * SLH-DSA Definitions
 **************************************************************************/

static const struct def_algo_slh_dsa_caps slh_dsa_keygen_capabilities[] = { {
	.parameter_set = DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHAKE_128F |
			 DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHAKE_192F |
			 DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHAKE_256F,
} };

static const struct def_algo_slh_dsa_caps slh_dsa_sig_capabilities_pure[] = { {
	.parameter_set = DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHAKE_128F |
			 DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHAKE_192F |
			 DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHAKE_256F,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
} };


static const struct def_algo_slh_dsa_caps slh_dsa_sig_capabilities_prehash[] = { {
	.parameter_set = DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHAKE_128F |
			 DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHAKE_192F |
			 DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHAKE_256F,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
	DEF_ALG_DOMAIN(.contextlength, 0, 1024, 8),
	.hashalg = ACVP_SHA3_512 | ACVP_SHA512 | ACVP_SHAKE256,
} };

#define LC_SLH_DSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_SLH_DSA,					\
	.algo = {							\
		.slh_dsa = {						\
			.slh_dsa_mode = DEF_ALG_SLH_DSA_MODE_KEYGEN,	\
			.capabilities.keygen = slh_dsa_keygen_capabilities,\
			.capabilities_num = ARRAY_SIZE(slh_dsa_keygen_capabilities),\
			}						\
		}							\
	}

#define LC_SLH_DSA_SIGGEN_TYPE(m)					\
	{								\
	.type = DEF_ALG_TYPE_SLH_DSA,					\
	.algo = {							\
		.slh_dsa = {						\
			.slh_dsa_mode = DEF_ALG_SLH_DSA_MODE_SIGGEN,	\
			.capabilities.siggen = m,			\
			.capabilities_num = ARRAY_SIZE(m),		\
			.deterministic = DEF_ALG_SLH_DSA_SIGGEN_NON_DETERMINISTIC |\
					 DEF_ALG_SLH_DSA_SIGGEN_DETERMINISTIC,\
			.interface = DEF_ALG_SLH_DSA_INTERFACE_EXTERNAL |\
				     DEF_ALG_SLH_DSA_INTERFACE_INTERNAL,\
			}						\
		}							\
	}

#define LC_SLH_DSA_SIGVER_TYPE(m)					\
	{								\
	.type = DEF_ALG_TYPE_SLH_DSA,					\
	.algo = {							\
		.slh_dsa = {						\
			.slh_dsa_mode = DEF_ALG_SLH_DSA_MODE_SIGVER,	\
			.capabilities.sigver = m,			\
			.capabilities_num = ARRAY_SIZE(m),		\
			.interface = DEF_ALG_SLH_DSA_INTERFACE_EXTERNAL |\
				     DEF_ALG_SLH_DSA_INTERFACE_INTERNAL,\
			}						\
		}							\
	}

#define LC_SLH_DSA							\
	LC_SLH_DSA_KEYGEN,						\
	LC_SLH_DSA_SIGGEN_TYPE(slh_dsa_sig_capabilities_pure),		\
	LC_SLH_DSA_SIGGEN_TYPE(slh_dsa_sig_capabilities_prehash),	\
	LC_SLH_DSA_SIGVER_TYPE(slh_dsa_sig_capabilities_pure),		\
	LC_SLH_DSA_SIGVER_TYPE(slh_dsa_sig_capabilities_prehash)

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
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),

	LC_HMAC(ACVP_HMACSHA2_256),
	LC_HMAC(ACVP_HMACSHA2_384),
	LC_HMAC(ACVP_HMACSHA2_512),

	LC_KDF_HMAC,

	LC_PBKDF(ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),

	LC_DRBG_HMAC,
	LC_DRBG_HASH,

	LC_HKDF,

	LC_EDDSA_KEYGEN,
	LC_EDDSA_SIGGEN,
	LC_EDDSA_SIGVER,

	LC_ML_DSA_KEYGEN_FULL,
	LC_ML_DSA_SIGGEN_FULL,
	LC_ML_DSA_SIGVER_FULL,

	LC_ML_KEM_KEYGEN_FULL,
	LC_ML_KEM_ENCAPDECAP_FULL,

	LC_SLH_DSA
};

static const struct def_algo lc_avx2[] = {
	LC_SHA3_ALGOS,

	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),

	LC_ML_DSA_KEYGEN_STRONG,
	LC_ML_DSA_SIGGEN_STRONG,
	LC_ML_DSA_SIGVER_STRONG,

	LC_ML_KEM_KEYGEN_STRONG,
	LC_ML_KEM_ENCAPDECAP_STRONG,

	LC_SLH_DSA
};

static const struct def_algo lc_shake_avx2_4x[] = {
	LC_SHAKE(ACVP_SHAKE128),
	LC_SHAKE(ACVP_SHAKE256),
};

static const struct def_algo lc_shake_armv8_2x[] = {
	LC_SHAKE(ACVP_SHAKE128),
	LC_SHAKE(ACVP_SHAKE256),
};

static const struct def_algo lc_avx512[] = {
	LC_SHA3_ALGOS
};

static const struct def_algo lc_arm_neon[] = {
	LC_SHA3_ALGOS,

	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),

	LC_ML_DSA_KEYGEN_STRONG,
	LC_ML_DSA_SIGGEN_STRONG,
	LC_ML_DSA_SIGVER_STRONG,

	/* ML-KEM not applicable - the ARMv7 is hard-wired into C */
};

static const struct def_algo lc_arm_asm[] = {
	LC_SHA3_ALGOS,

	LC_ML_DSA_KEYGEN_STRONG,
	LC_ML_DSA_SIGGEN_STRONG,
	LC_ML_DSA_SIGVER_STRONG,

	LC_ML_KEM_KEYGEN_STRONG,
	LC_ML_KEM_ENCAPDECAP_STRONG,

	LC_SLH_DSA
};

static const struct def_algo lc_arm_ce[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW,

	LC_SHA3_ALGOS,
	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),
};

static const struct def_algo lc_aesni[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW,

	/* Covering SHA-NI */
	LC_SHA_NO_LDT(ACVP_SHA256),
	//LC_SHA_NO_LDT(ACVP_SHA384),
	//LC_SHA_NO_LDT(ACVP_SHA512),
};

static const struct def_algo lc_riscv64[] = {
	LC_AES_CBC,
	LC_AES_CTR,
	LC_AES_KW,

	LC_SHA3_ALGOS,

	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),

	LC_ML_DSA_KEYGEN_FULL,
	LC_ML_DSA_SIGGEN_FULL,
	LC_ML_DSA_SIGVER_FULL,

	LC_ML_KEM_KEYGEN_FULL,
	LC_ML_KEM_ENCAPDECAP_FULL,
};

static const struct def_algo lc_riscv64_zbb[] = {
	LC_SHA3_ALGOS,
	LC_SHA_NO_LDT(ACVP_SHA256),
	LC_SHA_NO_LDT(ACVP_SHA384),
	LC_SHA_NO_LDT(ACVP_SHA512),
};

static const struct def_algo lc_riscv64_rvv[] = {
	LC_ML_DSA_KEYGEN_FULL,
	LC_ML_DSA_SIGGEN_FULL,
	LC_ML_DSA_SIGVER_FULL,

	LC_ML_KEM_KEYGEN_FULL,
	LC_ML_KEM_ENCAPDECAP_FULL,
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

/* C cipher implementation, C block-chaining **********************************/
	{
		SET_IMPLEMENTATION(lc_c),
		.algo_name = "leancrypto",
		.processor = "",
		.impl_name = "Kernel_C"
	},

/* AVX2 cipher implementation, ************************************************/
	{
		SET_IMPLEMENTATION(lc_avx2),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "Kernel_AVX2"
	},

/* AVX2 cipher implementation, ************************************************/
	{
		SET_IMPLEMENTATION(lc_shake_avx2_4x),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "Kernel_AVX2_4X"
	},

/* AVX512 cipher implementation, **********************************************/
	{
		SET_IMPLEMENTATION(lc_avx512),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "Kernel_AVX512"
	},

/* AESNI cipher implementation, ***********************************************/
	{
		SET_IMPLEMENTATION(lc_aesni),
		.algo_name = "leancrypto",
		.processor = "X86",
		.impl_name = "Kernel_AESNI"
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

/* ARMv8 cipher implementation, ***********************************************/
	{
		SET_IMPLEMENTATION(lc_shake_armv8_2x),
		.algo_name = "leancrypto",
		.processor = "ARM64",
		.impl_name = "ARM_2X"
	},

/* RISC-V 64 cipher assembler implementation, *********************************/
	{
		SET_IMPLEMENTATION(lc_riscv64),
		.algo_name = "leancrypto",
		.processor = "RISC-V 64",
		.impl_name = "RISCV64"
	},

/* RISC-V 64 Zbb cipher assembler implementation, *****************************/
	{
		SET_IMPLEMENTATION(lc_riscv64_zbb),
		.algo_name = "leancrypto",
		.processor = "RISC-V 64",
		.impl_name = "RISCV64_ZBB"
	},
/* RISC-V 64 RVV cipher assembler implementation, *****************************/
	{
		SET_IMPLEMENTATION(lc_riscv64_rvv),
		.algo_name = "leancrypto",
		.processor = "RISC-V 64",
		.impl_name = "RISCV64_RVV"
	},

};

ACVP_DEFINE_CONSTRUCTOR(lc_register)
static void lc_register(void)
{
	acvp_register_algo_map(lc_algo_map,
			       ARRAY_SIZE(lc_algo_map));
}

ACVP_EXTENSION(lc_algo_map)
