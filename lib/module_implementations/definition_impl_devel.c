/* Development module definition
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

#include "definition.h"
#include "definition_impl_common.h"

/**************************************************************************
 * Safeprimes
 **************************************************************************/
#if 0
#define DEVEL_SAFEPRIMES(mode, groups) GENERIC_SAFEPRIMES(mode, groups)
#else
#define DEVEL_SAFEPRIMES(mode, groups)
#endif

/**************************************************************************
 * SP800-56A rev3 FFC
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_dh_r3_prereqs[] = {
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
	{
		.algorithm = "SafePrimes",
		.valvalue = "same"
	},
	{
		.algorithm = "SP800-108",
		.valvalue = "same"
	},
};

const struct def_algo_kas_kdf_onestepkdf_aux devel_kas_ffc_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };

const struct def_algo_kas_kdf_twostepkdf devel_kas_ffc_twostepkdf[] = { {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL },
	.literal = "0123456789abcdef",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_COUNTER,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
}, {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL,
				     DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT,
				     DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID },
	.literal = "fedcba9876543210",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_FEEDBACK,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
} };

const struct def_algo_kas_mac_method devel_ffc_r3_mac[] = { {
	.mac = ACVP_HMACSHA2_256,
	.key_length = 128,
	.mac_length = 128,
}, {
	.mac = ACVP_HMACSHA2_512,
	.key_length = 128,
	.mac_length = 128,
} };

const struct def_algo_kas_ffc_r3_schema devel_ffc_r3_schema[] = { {
	.schema = DEF_ALG_KAS_FFC_DH_EPHEM,
	.kas_ffc_role = DEF_ALG_KAS_FFC_R3_INITIATOR |
			DEF_ALG_KAS_FFC_R3_RESPONDER,
	.onestepkdf = {
			.aux_function = devel_kas_ffc_onestepkdf_aux,
			.aux_function_num = ARRAY_SIZE(devel_kas_ffc_onestepkdf_aux),
			.fixed_info_pattern_type = {
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
			.literal = "affedeadbeef",
			.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.twostepkdf = devel_kas_ffc_twostepkdf,
	.twostepkdf_num = ARRAY_SIZE(devel_kas_ffc_twostepkdf),
	.key_confirmation_method = {
		.kc_direction = DEF_ALG_KAS_R3_UNILATERAL |
				DEF_ALG_KAS_R3_BILATERAL,
		.kcrole = DEF_ALG_KAS_R3_PROVIDER |
			  DEF_ALG_KAS_R3_RECIPIENT,
		.mac = devel_ffc_r3_mac,
		.mac_entries = ARRAY_SIZE(devel_ffc_r3_mac),
		},
	.length = 1024,
} };

#define DEVEL_KAS_FFC_R3						\
	{								\
	.type = DEF_ALG_TYPE_KAS_FFC_R3,				\
	.algo.kas_ffc_r3 = {						\
		DEF_PREREQS(devel_dh_r3_prereqs),			\
		.kas_ffc_function = DEF_ALG_KAS_FFC_R3_KEYPAIRGEN |	\
				    DEF_ALG_KAS_FFC_R3_PARTIALVAL |	\
				    DEF_ALG_KAS_FFC_R3_FULLVAL,		\
		.iut_identifier = "1234567890abcdef",			\
		.schema = devel_ffc_r3_schema,				\
		.schema_num = ARRAY_SIZE(devel_ffc_r3_schema),		\
		.domain_parameter = ACVP_DH_MODP_2048,			\
		},							\
	}
#else
#define DEVEL_KAS_FFC_R3
#endif


/**************************************************************************
 * SP800-56A rev3 ECC
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_ecdh_r3_prereqs[] = {
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
	{
		.algorithm = "SP800-108",
		.valvalue = "same"
	},
};

const struct def_algo_kas_kdf_onestepkdf_aux devel_kas_ecc_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };

const struct def_algo_kas_kdf_twostepkdf devel_kas_ecc_twostepkdf[] = { {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL },
	.literal = "0123456789abcdef",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_COUNTER,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
}, {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL,
				     DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT,
				     DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID },
	.literal = "fedcba9876543210",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_FEEDBACK,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
} };

const struct def_algo_kas_mac_method devel_ecc_r3_mac[] = { {
	.mac = ACVP_HMACSHA2_256,
	.key_length = 128,
	.mac_length = 128,
}, {
	.mac = ACVP_HMACSHA2_512,
	.key_length = 128,
	.mac_length = 128,
} };

const struct def_algo_kas_ecc_r3_schema devel_ecc_r3_schema[] = { {
	.schema = DEF_ALG_KAS_ECC_R3_FULL_UNIFIED,
	.kas_ecc_role = DEF_ALG_KAS_ECC_R3_INITIATOR |
			DEF_ALG_KAS_ECC_R3_RESPONDER,
	.onestepkdf = {
			.aux_function = devel_kas_ecc_onestepkdf_aux,
			.aux_function_num = ARRAY_SIZE(devel_kas_ecc_onestepkdf_aux),
			.fixed_info_pattern_type = {
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
			.literal = "affedeadbeef",
			.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.twostepkdf = devel_kas_ecc_twostepkdf,
	.twostepkdf_num = ARRAY_SIZE(devel_kas_ecc_twostepkdf),
	.key_confirmation_method = {
		.kc_direction = DEF_ALG_KAS_R3_UNILATERAL |
				DEF_ALG_KAS_R3_BILATERAL,
		.kcrole = DEF_ALG_KAS_R3_PROVIDER |
			  DEF_ALG_KAS_R3_RECIPIENT,
		.mac = devel_ecc_r3_mac,
		.mac_entries = ARRAY_SIZE(devel_ecc_r3_mac),
		},
	.length = 1024,
} };

#define DEVEL_KAS_ECC_R3						\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC_R3,				\
	.algo.kas_ecc_r3 = {						\
		DEF_PREREQS(devel_ecdh_r3_prereqs),			\
		.kas_ecc_function = DEF_ALG_KAS_ECC_R3_KEYPAIRGEN |	\
				    DEF_ALG_KAS_ECC_R3_PARTIALVAL |	\
				    DEF_ALG_KAS_ECC_R3_FULLVAL,		\
		.iut_identifier = "1234567890abcdef",			\
		.schema = devel_ecc_r3_schema,				\
		.schema_num = ARRAY_SIZE(devel_ecc_r3_schema),		\
		.domain_parameter = ACVP_NISTP256 | ACVP_NISTP384 |	\
				    ACVP_NISTP521,			\
		},							\
	}
#else
#define DEVEL_KAS_ECC_R3
#endif

/**************************************************************************
 * SP800-56A rev3 ECC SSC
 **************************************************************************/
#if 0
#define DEVEL_KAS_ECC_SSC_R3						\
 	GENERIC_KAS_ECC_SSC_R3(ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521),\
 	GENERIC_KAS_ECC_SSC_R3_HASH(ACVP_NISTP256 | ACVP_NISTP384 |	\
				    ACVP_NISTP521, ACVP_SHA3_512),	\
 	GENERIC_KAS_FFC_SSC_R3(ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |	\
			       ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |	\
			       ACVP_DH_MODP_8192),			\
	GENERIC_KAS_FFC_SSC_R3_HASH(ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |\
				    ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |\
				    ACVP_DH_MODP_8192, ACVP_SHA512)
#else
#define DEVEL_KAS_ECC_SSC_R3
#endif

/**************************************************************************
 * SP800-56B rev2
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kas_ifc_prereqs[] = {
	{
		.algorithm = "RSA",
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

const struct def_algo_kas_kdf_onestepkdf_aux devel_kas_ifc_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };

const struct def_algo_kas_kdf_twostepkdf devel_kas_ifc_twostepkdf[] = { {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL },
	.literal = "0123456789abcdef",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_COUNTER,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
}, {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL,
				     DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT,
				     DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID },
	.literal = "fedcba9876543210",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_FEEDBACK,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
} };

const struct def_algo_kas_mac_method devel_kas_ifc_mac[] = { {
	.mac = ACVP_HMACSHA2_256,
	.key_length = 128,
	.mac_length = 128,
}, {
	.mac = ACVP_HMACSHA2_512,
	.key_length = 128,
	.mac_length = 128,
} };

const struct def_algo_kas_ifc_schema devel_kas_ifc_schema_kas[] = { {
	.schema = DEF_ALG_KAS_IFC_KAS1_PARTY_V,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.onestepkdf = {
		.aux_function = devel_kas_ifc_onestepkdf_aux,
		.aux_function_num = ARRAY_SIZE(devel_kas_ifc_onestepkdf_aux),
		.fixed_info_pattern_type = {
			DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
		.literal = "affedeadbeef",
		.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.twostepkdf = devel_kas_ifc_twostepkdf,
	.twostepkdf_num = ARRAY_SIZE(devel_kas_ifc_twostepkdf),
	.mac = devel_kas_ifc_mac,
	.mac_entries = ARRAY_SIZE(devel_kas_ifc_mac),
	.length = 1024,
} };

const struct def_algo_kas_ifc_schema devel_kas_ifc_schema_kts[] = { {
	.schema = DEF_ALG_KAS_IFC_KTS_OAEP_BASIC,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.kts_method = {
		.hashalg = ACVP_SHA256 | ACVP_SHA3_384,
		.supports_null_association_data = true,
		.associated_data_pattern_type = {
			DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
		.literal = "affeaffeaffe",
		.associated_data_pattern_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.mac = devel_kas_ifc_mac,
	.mac_entries = ARRAY_SIZE(devel_kas_ifc_mac),
	.length = 1024,
} };

#define DEVEL_KAS_IFC							\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARTIALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
				DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,	\
				DEF_ALG_KAS_IFC_RSAKPG1_CRT },		\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,		\
				DEF_ALG_RSA_MODULO_8192,		\
				DEF_ALG_RSA_MODULO_2048 },		\
		.keygen.fixedpubexp = "010001",				\
		.schema = devel_kas_ifc_schema_kas,			\
		.schema_num = ARRAY_SIZE(devel_kas_ifc_schema_kas),	\
		},							\
	},								\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARTIALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
				DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,	\
				DEF_ALG_KAS_IFC_RSAKPG1_CRT },		\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,		\
				DEF_ALG_RSA_MODULO_8192,		\
				DEF_ALG_RSA_MODULO_2048 },		\
		.keygen.fixedpubexp = "010001",				\
		.schema = devel_kas_ifc_schema_kts,			\
		.schema_num = ARRAY_SIZE(devel_kas_ifc_schema_kts),	\
		},							\
	}
#else
#define DEVEL_KAS_IFC
#endif

/**************************************************************************
 * SP800-56B rev2 OAEP
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kas_ifc_prereqs[] = {
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

const struct def_algo_kas_ifc_schema devel_kas_ifc_schema_kts[] = { {
	.schema = DEF_ALG_KAS_IFC_KTS_OAEP_BASIC,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.kts_method = {
		.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512 | ACVP_SHA3_224 | ACVP_SHA3_256 |
			   ACVP_SHA3_384 | ACVP_SHA3_512,
		.supports_null_association_data = true,
		.associated_data_pattern_type = {
			DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO
			},
		.associated_data_pattern_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.length = 768,
} };

#define DEVEL_RSA_OAEP							\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_PARTIALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC },\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_2048,		\
				       DEF_ALG_RSA_MODULO_3072,		\
				       DEF_ALG_RSA_MODULO_4096,		\
				       DEF_ALG_RSA_MODULO_6144,		\
				       DEF_ALG_RSA_MODULO_8192 },	\
		.keygen.fixedpubexp = "010001",				\
		.schema = devel_kas_ifc_schema_kts,			\
		.schema_num = ARRAY_SIZE(devel_kas_ifc_schema_kts),	\
		},							\
	}
#else
#define DEVEL_RSA_OAEP
#endif

#if 0
static const struct def_algo_prereqs devel_kas_ifc_ssc_prereqs[] = {
	{
		.algorithm = "RSA",
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

const struct def_algo_kas_ifc_ssc_schema devel_kas_ifc_ssc_schema_kts[] = { {
	.schema = DEF_ALG_KAS_IFC_SSC_KAS1,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER
} };

#define DEVEL_RSA_SSC							\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_ssc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_SSC,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC },\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_2048,		\
				       DEF_ALG_RSA_MODULO_3072,		\
				       DEF_ALG_RSA_MODULO_4096,		\
				       DEF_ALG_RSA_MODULO_6144,		\
				       DEF_ALG_RSA_MODULO_8192,	},	\
		.keygen.fixedpubexp = "010001",				\
		.ssc_schema = devel_kas_ifc_ssc_schema_kts,		\
		.ssc_schema_num = ARRAY_SIZE(devel_kas_ifc_ssc_schema_kts),\
		},							\
	}
#else
#define DEVEL_RSA_SSC
#endif

/**************************************************************************
 * SP800-56B rev2 SSC
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kas_ifc_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

const struct def_algo_kas_ifc_ssc_schema devel_kas_ifc_ssc_schema_kas[] = { {
	.schema = DEF_ALG_KAS_IFC_SSC_KAS1,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
} };

#define DEVEL_KAS_IFC_SSC						\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_SSC,			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
				DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,	\
				DEF_ALG_KAS_IFC_RSAKPG1_CRT },		\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,		\
				DEF_ALG_RSA_MODULO_8192,		\
				DEF_ALG_RSA_MODULO_2048 },		\
		.keygen.fixedpubexp = "010001",				\
		.ssc_schema = devel_kas_ifc_ssc_schema_kas,		\
		.ssc_schema_num = ARRAY_SIZE(devel_kas_ifc_ssc_schema_kas),\
		},							\
	}
#else
#define DEVEL_KAS_IFC_SSC
#endif

/**************************************************************************
 * SP800-56C rev 1 Onestep KDF
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kdf_onestep_prereqs[] = {
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

const struct def_algo_kas_kdf_onestepkdf_aux devel_kas_kdf_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };


#define DEVEL_KAS_KDF_ONESTEP						\
	{								\
	.type = DEF_ALG_TYPE_KDF_ONESTEP,				\
	.algo.kdf_onestep = {						\
		DEF_PREREQS(devel_kdf_onestep_prereqs),			\
		.kdf_spec = DEF_ALG_KDF_SP800_56Crev2,			\
		.onestep = 	{					\
			.aux_function = devel_kas_kdf_onestepkdf_aux,	\
			.aux_function_num = ARRAY_SIZE(devel_kas_kdf_onestepkdf_aux),\
			.fixed_info_pattern_type = {			\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL	\
				},					\
			.literal = "affedeadbeef",			\
			.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,\
			},						\
		.length = 1024,						\
		DEF_ALG_DOMAIN(.zlen, 256, 512, 128),			\
		}							\
	}
#else
#define DEVEL_KAS_KDF_ONESTEP
#endif

/**************************************************************************
 * SP800-56C rev 1 Twostep KDF
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kdf_twostep_prereqs[] = {
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

const struct def_algo_kas_kdf_twostepkdf devel_kdf_twostepkdf[] = { {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL },
	.literal = "0123456789abcdef",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_COUNTER,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
}, {
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT,
	.fixed_info_pattern_type = { DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				     DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL,
				     DEF_ALG_KAS_KDF_FI_PATTERN_CONTEXT,
				     DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID },
	.literal = "fedcba9876543210",
	.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
	.kdf_108 = {
		.kdf_108_type = DEF_ALG_KDF_108_FEEDBACK,
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |
			  ACVP_HMACSHA2_512,
		DEF_ALG_DOMAIN(.supported_lengths, 8, 4096, 8),
		.fixed_data_order = DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA,
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,
		.supports_empty_iv = false,
		.requires_empty_iv = false
		}
} };

#define DEVEL_KAS_KDF_TWOSTEP						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TWOSTEP,				\
	.algo.kdf_twostep = {						\
		DEF_PREREQS(devel_kdf_twostep_prereqs),			\
		.twostep = devel_kdf_twostepkdf,			\
		.twostep_num = ARRAY_SIZE(devel_kdf_twostepkdf),	\
		.length = 1024,						\
		DEF_ALG_DOMAIN(.zlen, 256, 512, 128),			\
		},							\
	}
#else
#define DEVEL_KAS_KDF_TWOSTEP
#endif

/**************************************************************************
 * RSA decryption primtive
 **************************************************************************/
#if 0

static const struct def_algo_prereqs devel_rsa_prereqs[] = {
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define DEVEL_RSA_DEC_PRIMITIVE10					\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE,\
			DEF_PREREQS(devel_rsa_prereqs),\
			}						\
		}							\
	}

#else
#define DEVEL_RSA_DEC_PRIMITIVE10
#endif

#if 0

static const struct def_algo_prereqs devel_rsa_prereqs[] = {
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_rsa_component_dec devel_rsa_component_dec_alg[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_CRT,
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_FIXED,
	.fixedpubexp = "010001",
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_CRT,
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_FIXED,
	.fixedpubexp = "010001",
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_CRT,
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_FIXED,
	.fixedpubexp = "010001",
} };

#define DEVEL_RSA_DEC_PRIMITIVE56Br2					\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE,\
			DEF_PREREQS(devel_rsa_prereqs),			\
			.algspecs.component_dec = devel_rsa_component_dec_alg,\
			.algspecs_num = ARRAY_SIZE(devel_rsa_component_dec_alg),\
			}						\
		}							\
	}

#else
#define DEVEL_RSA_DEC_PRIMITIVE56Br2
#endif

/**************************************************************************
 * RSA decryption primtiive
 **************************************************************************/
#if 0

static const struct def_algo_prereqs devel_kdf_tpm_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define DEVEL_KDF_TPM							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TPM,					\
	.algo = {							\
		.kdf_tpm = {						\
			DEF_PREREQS(devel_kdf_tpm_prereqs),		\
			}						\
		}							\
	}

#else
#define DEVEL_KDF_TPM
#endif

/**************************************************************************
 * Conditioning component
 **************************************************************************/
#if 0

#define DEVEL_COND_COMP							\
	{								\
	.type = DEF_ALG_TYPE_COND_COMP,					\
	.algo = {							\
		.cond_comp = {						\
			.mode = ACVP_COND_COMP_CBC_MAC,			\
			.keylen = DEF_ALG_SYM_KEYLEN_256,		\
			DEF_ALG_DOMAIN(.payload_len, 128, 512, 128),	\
			},						\
		},							\
	}

#else
#define DEVEL_COND_COMP
#endif

/**************************************************************************
 * TLS Definitions
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devell_kdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define DEVEL_KDF11							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(devell_kdf_prereqs),			\
		.tls_version = DEF_ALG_KDF_TLS_1_0_1_1,			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384			\
		}							\
	}
#define DEVEL_KDF12							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS12,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(devell_kdf_prereqs),			\
		.tls_version = DEF_ALG_KDF_TLS_1_2,			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384			\
		}							\
	}

#define DEVEL_KDF							\
	DEVEL_KDF11,							\
	DEVEL_KDF12

#else
#define DEVEL_KDF
#endif

/**************************************************************************
 * ANSI X963 Definitions
 **************************************************************************/
#if 0
#define DEVEL_ANSI_X963							\
	{								\
	.type = DEF_ALG_TYPE_ANSI_X963,					\
	.algo.ansi_x963 = {						\
		.prereqvals = {						\
			.algorithm = "SHA",				\
			.valvalue = "same"				\
			},						\
		.hashalg = ACVP_SHA256 | ACVP_SHA384,			\
		DEF_ALG_DOMAIN(.shared_info_len, 0, 1024, 8),		\
		DEF_ALG_DOMAIN(.key_data_len, 128, 4096, 8),		\
		.field_size[0] = 256,					\
		}							\
	}

#else
#define DEVEL_ANSI_X963
#endif

/**************************************************************************
 * TLS 1.3 Definitions
 **************************************************************************/
#if 0
static const struct def_algo_prereqs devel_kdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define DEVEL_TLS13_KDF							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS13,					\
	.algo.kdf_tls13 = {						\
		DEF_PREREQS(devel_kdf_prereqs),				\
		.hashalg = ACVP_SHA256 | ACVP_SHA384,			\
		.running_mode = DEF_ALG_KDF_TLS13_MODE_DHE		\
		}							\
	}
#else
#define DEVEL_TLS13_KDF
#endif

/**************************************************************************
 * XOF definitions
 **************************************************************************/
#if 0
#define DEVEL_XOF(shake_def)						\
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

#define DEVEL_KMAC(kmac_def)						\
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
#else
#define DEVEL_KMAC(kmac_def)
#define DEVEL_XOF(shake_def)
#endif

/**************************************************************************
 * Generic definitions
 **************************************************************************/

#if 0
#define DEVEL_AES_XTS							\
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
	.algo.sym.xts_data_unit_len_matches_payload = false,		\
	.algo.sym.xts_data_unit_len = { 256, 1024 }			\
	}

#else
#define DEVEL_AES_XTS
#endif

#if 0
static const struct def_algo_prereqs qcom_kdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};
#define QCOM_HKDF							\
	{								\
	.type = DEF_ALG_TYPE_HKDF,					\
	.algo.hkdf = {							\
		DEF_PREREQS(qcom_kdf_prereqs),				\
		.mac_salt_method = DEF_ALG_KAS_HKDF_MAC_SALT_DEFAULT,	\
		.fixed_info_pattern_type = {				\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL },	\
		.literal = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000020000",\
		.cipher_spec = {					\
			.macalg = ACVP_SHA256 | ACVP_SHA512,		\
			.z = { 256 },					\
			.l = 512,					\
			}						\
		}							\
	}
#else
#define QCOM_HKDF
#endif

#if 0
static const struct def_algo_prereqs nss_rsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define NSS_DSA_PQG_COMMON(x, L, N, hashes)				\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = x,					\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(nss_rsa_prereqs),			\
			.dsa_pq_gen_method = DEF_ALG_DSA_PROVABLE_PQ_GEN, \
			.dsa_g_gen_method = DEF_ALG_DSA_CANONICAL_G_GEN, \
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define NSS_DSA_PQGGEN(L, N, hashes)					\
		NSS_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGGEN, L, N, hashes)
#else
#define NSS_DSA_PQGGEN(L, N, hashes)
#endif

#if 0
static const struct def_algo_prereqs tests_kdf_onestep_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};
static const struct def_algo_kas_kdf_onestepkdf_aux kas_kdf_onestepkdf_aux[] = { {
	.auxfunc = ACVP_SHA256,
	.length = 256,
} };

#define ONESTEPNOCTR							\
	{								\
	.type = DEF_ALG_TYPE_KDF_ONESTEP,				\
	.algo.kdf_onestep = {						\
		DEF_PREREQS(tests_kdf_onestep_prereqs),			\
		.onestep = {						\
			.aux_function = kas_kdf_onestepkdf_aux,\
			.aux_function_num = ARRAY_SIZE(kas_kdf_onestepkdf_aux),\
			.fixed_info_pattern_type = {			\
				DEF_ALG_KAS_KDF_FI_PATTERN_ALGORITHM_ID,\
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,\
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO \
				},					\
			.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,\
			},						\
		.zlen[0] = 384,						\
		}							\
	}
#else
#define ONESTEPNOCTR
#endif

#if 0
static const struct def_algo_prereqs devel_rsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define DEVEL_RSA_KEYGEN_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256,	\
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_2POW100 |		\
			 DEF_ALG_RSA_PRIMETEST_2POWSECSTR,		\

static const struct def_algo_rsa_keygen_caps devel_rsa_keygen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.p_mod8 = 0,
	.q_mod8 = 7,
	DEVEL_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.p_mod8 = 1,
	.q_mod8 = 3,
	DEVEL_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.p_mod8 = 5,
	.q_mod8 = 0,
	DEVEL_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_8192,
	DEVEL_RSA_KEYGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_keygen devel_rsa_keygen = {
	.rsa_randpq = DEF_ALG_RSA_PQ_PROBABLE_WITH_PROVABLE_AUX_PRIMES,
	.capabilities = devel_rsa_keygen_caps,
	.capabilities_num = ARRAY_SIZE(devel_rsa_keygen_caps),
};

static const struct def_algo_rsa_keygen_gen devel_rsa_keygen_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_STANDARD,
};

#define DEVEL_RSA_186_5_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = DEF_ALG_RSA_186_5,			\
			.rsa_mode = DEF_ALG_RSA_MODE_KEYGEN,		\
			DEF_PREREQS(devel_rsa_prereqs),			\
			.gen_info.keygen = &devel_rsa_keygen_gen,	\
			.algspecs.keygen = &devel_rsa_keygen,		\
			.algspecs_num = 1,				\
			}						\
		}							\
	}

static const struct def_algo_rsa_keygen_gen devel_rsa_keygen_crt_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_CRT,
};

#define DEVEL_RSA_186_5_KEYGEN_CRT					\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = DEF_ALG_RSA_186_5,			\
			.rsa_mode = DEF_ALG_RSA_MODE_KEYGEN,		\
			DEF_PREREQS(devel_rsa_prereqs),			\
			.gen_info.keygen = &devel_rsa_keygen_crt_gen,	\
			.algspecs.keygen = &devel_rsa_keygen,		\
			.algspecs_num = 1,				\
			}						\
		}							\
	}

#define DEVEL_RSA_SIGGEN_CAPS_COMMON					\
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |		\
		   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |	\
		   ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |	\
		   ACVP_SHA3_512,

static const struct def_algo_rsa_siggen_caps devel_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	DEVEL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	DEVEL_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	DEVEL_RSA_SIGGEN_CAPS_COMMON
} };

#define DEVEL_RSA_SIGGEN_CAPS_PSS_COMMON				\
	.hashalg = ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |		\
		   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |	\
		   ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |	\
		   ACVP_SHA3_512 | ACVP_SHAKE128 | ACVP_SHAKE256,

static const struct def_algo_rsa_siggen_caps devel_rsa_siggen_caps_pss[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	DEVEL_RSA_SIGGEN_CAPS_PSS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_128,
	.saltlen = DEF_ALG_RSA_PSS_SALT_HASHLEN,
	DEVEL_RSA_SIGGEN_CAPS_PSS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_128 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_256,
	.saltlen = DEF_ALG_RSA_PSS_SALT_VALUE,
	.saltlen_bytes = 13,
	DEVEL_RSA_SIGGEN_CAPS_PSS_COMMON
} };

static const struct def_algo_rsa_siggen devel_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = devel_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(devel_rsa_siggen_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = devel_rsa_siggen_caps_pss,
	.capabilities_num = ARRAY_SIZE(devel_rsa_siggen_caps_pss),
} };

#define DEVEL_RSA_186_5_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = DEF_ALG_RSA_186_5,			\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGGEN,		\
			DEF_PREREQS(devel_rsa_prereqs),			\
			.algspecs.siggen = devel_rsa_siggen,		\
			.algspecs_num = ARRAY_SIZE(devel_rsa_siggen),	\
			}						\
		}							\
	}

#define DEVEL_RSA_SIGVER_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |	\
		   ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |	\
		   ACVP_SHA3_512,

static const struct def_algo_rsa_sigver_caps devel_rsa_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	DEVEL_RSA_SIGVER_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	DEVEL_RSA_SIGVER_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	DEVEL_RSA_SIGVER_CAPS_COMMON
} };

#define DEVEL_RSA_SIGVER_CAPS_PSS_COMMON				\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512 | ACVP_SHA512224 | ACVP_SHA512256 |	\
		   ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |	\
		   ACVP_SHA3_512 | ACVP_SHAKE128 | ACVP_SHAKE256,

static const struct def_algo_rsa_sigver_caps devel_rsa_sigver_caps_pss[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1,
	.saltlen = DEF_ALG_RSA_PSS_SALT_ZERO,
	DEVEL_RSA_SIGVER_CAPS_PSS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_128,
	.saltlen = DEF_ALG_RSA_PSS_SALT_HASHLEN,
	DEVEL_RSA_SIGVER_CAPS_PSS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
	.mask_function = DEF_ALG_RSA_MASK_FUNC_MGF1 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_128 |
			 DEF_ALG_RSA_MASK_FUNC_SHAKE_256,
	.saltlen = DEF_ALG_RSA_PSS_SALT_VALUE,
	.saltlen_bytes = 13,
	DEVEL_RSA_SIGVER_CAPS_PSS_COMMON
} };

static const struct def_algo_rsa_sigver devel_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = devel_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(devel_rsa_sigver_caps),
}, {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PSS,
	.capabilities = devel_rsa_sigver_caps_pss,
	.capabilities_num = ARRAY_SIZE(devel_rsa_sigver_caps),
} };

static const struct def_algo_rsa_sigver_gen devel_rsa_sigver_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
};

#define DEVEL_RSA_186_5_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.revision = DEF_ALG_RSA_186_5,			\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGVER,		\
			DEF_PREREQS(devel_rsa_prereqs),			\
			.gen_info.sigver = &devel_rsa_sigver_gen,	\
			.algspecs.sigver = devel_rsa_sigver,		\
			.algspecs_num = ARRAY_SIZE(devel_rsa_sigver),	\
			}						\
		}							\
	}
#define DEVEL_RSA_186_5							\
	DEVEL_RSA_186_5_KEYGEN,						\
	DEVEL_RSA_186_5_KEYGEN_CRT,					\
	DEVEL_RSA_186_5_SIGGEN,						\
	DEVEL_RSA_186_5_SIGVER
#else
#define DEVEL_RSA_186_5
#endif

#if 0
static const struct def_algo_prereqs tests_lms_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};
static const struct def_algo_lms_specific_caps lms_specific_capabilities[] = { {
	.lms_mode = DEF_ALG_LMS_LMS_SHA256_M24_H5,
	.lmots_mode = DEF_ALG_LMS_LMOTS_SHA256_N24_W2,
}, {
	.lms_mode = DEF_ALG_LMS_LMS_SHAKE_M24_H25,
	.lmots_mode = DEF_ALG_LMS_LMOTS_SHAKE_N24_W1,
} };

#define LMS_GENERAL_COMMON(mode)					\
	{								\
	.type = DEF_ALG_TYPE_LMS,					\
	.algo = {							\
		.lms = {						\
			.lms_mode = mode,				\
			DEF_PREREQS(tests_lms_prereqs),			\
			.lms_modes = DEF_ALG_LMS_LMS_SHA256_M24_H5 |	\
				     DEF_ALG_LMS_LMS_SHA256_M24_H10,	\
			.lmots_modes = DEF_ALG_LMS_LMOTS_SHA256_N24_W1 |\
				       DEF_ALG_LMS_LMOTS_SHA256_N24_W8,	\
			}						\
		}							\
	}

#define LMS_SPECIFIC_COMMON(mode)					\
	{								\
	.type = DEF_ALG_TYPE_LMS,					\
	.algo = {							\
		.lms = {						\
			.lms_mode = mode,				\
			DEF_PREREQS(tests_lms_prereqs),			\
			.specific_capabilities = lms_specific_capabilities,\
			.specific_capabilities_num = ARRAY_SIZE(lms_specific_capabilities),\
			}						\
		}							\
	}

#define LMS								\
	LMS_GENERAL_COMMON(DEF_ALG_LMS_MODE_KEYGEN),			\
	LMS_GENERAL_COMMON(DEF_ALG_LMS_MODE_SIGGEN),			\
	LMS_GENERAL_COMMON(DEF_ALG_LMS_MODE_SIGVER),			\
	LMS_SPECIFIC_COMMON(DEF_ALG_LMS_MODE_KEYGEN),			\
	LMS_SPECIFIC_COMMON(DEF_ALG_LMS_MODE_SIGGEN),			\
	LMS_SPECIFIC_COMMON(DEF_ALG_LMS_MODE_SIGVER)

#else
#define LMS
#endif

#if 1
static const struct def_algo_slh_dsa_caps slh_dsa_keygen_capabilities[] = { {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_128S | DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHA2_128F | DEF_ALG_SLH_DSA_SHAKE_128F |
			 DEF_ALG_SLH_DSA_SHA2_192S | DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHA2_192F | DEF_ALG_SLH_DSA_SHAKE_192F |
			 DEF_ALG_SLH_DSA_SHA2_256S | DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHA2_256F | DEF_ALG_SLH_DSA_SHAKE_256F,
} };
static const struct def_algo_slh_dsa_caps slh_dsa_sig_capabilities[] = { {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_128S | DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHA2_256F | DEF_ALG_SLH_DSA_SHAKE_128F,
	DEF_ALG_DOMAIN(.messagelength, 8, 65536, 8),
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_192S | DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHA2_128F | DEF_ALG_SLH_DSA_SHAKE_192F,
	DEF_ALG_DOMAIN(.messagelength, 16, 65536, 16),
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_256S | DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHA2_192F | DEF_ALG_SLH_DSA_SHAKE_256F,
	DEF_ALG_DOMAIN(.messagelength, 32, 65536, 32),
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_128S | DEF_ALG_SLH_DSA_SHAKE_128S |
			 DEF_ALG_SLH_DSA_SHA2_128F | DEF_ALG_SLH_DSA_SHAKE_128F |
			 DEF_ALG_SLH_DSA_SHA2_192S | DEF_ALG_SLH_DSA_SHAKE_192S |
			 DEF_ALG_SLH_DSA_SHA2_192F | DEF_ALG_SLH_DSA_SHAKE_192F |
			 DEF_ALG_SLH_DSA_SHA2_256S | DEF_ALG_SLH_DSA_SHAKE_256S |
			 DEF_ALG_SLH_DSA_SHA2_256F | DEF_ALG_SLH_DSA_SHAKE_256F,
	DEF_ALG_DOMAIN(.messagelength, 128, 65536, 128),
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_128S,
	.messagelength = { 8, 16, 32, 128 },
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_192S,
	.messagelength = { 8 },
}, {
	.parameter_set = DEF_ALG_SLH_DSA_SHA2_256S,
	.messagelength = { 65536 },
} };

#define DEVEL_SLH_DSA_KEYGEN						\
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

#define DEVEL_SLH_DSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_SLH_DSA,					\
	.algo = {							\
		.slh_dsa = {						\
			.slh_dsa_mode = DEF_ALG_SLH_DSA_MODE_SIGGEN,	\
			.capabilities.siggen = slh_dsa_sig_capabilities,\
			.capabilities_num = ARRAY_SIZE(slh_dsa_sig_capabilities),\
			.deterministic = DEF_ALG_SLH_DSA_SIGGEN_NON_DETERMINISTIC |\
					 DEF_ALG_SLH_DSA_SIGGEN_DETERMINISTIC,\
			}						\
		}							\
	}

#define DEVEL_SLH_DSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_SLH_DSA,					\
	.algo = {							\
		.slh_dsa = {						\
			.slh_dsa_mode = DEF_ALG_SLH_DSA_MODE_SIGVER,	\
			.capabilities.sigver = slh_dsa_sig_capabilities,\
			.capabilities_num = ARRAY_SIZE(slh_dsa_sig_capabilities),\
			}						\
		}							\
	}

#define DEVEL_SLH_DSA							\
	DEVEL_SLH_DSA_KEYGEN,						\
	DEVEL_SLH_DSA_SIGGEN,						\
	DEVEL_SLH_DSA_SIGVER
#else
#define DEVEL_SLH_DSA
#endif

/**************************************************************************
 * Devel Implementation Definitions
 **************************************************************************/
static const struct def_algo devel[] = {
	DEVEL_KAS_FFC_R3
	DEVEL_KAS_ECC_R3
	DEVEL_KAS_ECC_SSC_R3
	DEVEL_KAS_IFC
	DEVEL_RSA_OAEP

	DEVEL_RSA_SSC

	DEVEL_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYGENERATION,
			 ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |
			 ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |
			 ACVP_DH_MODP_8192)
	DEVEL_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYVERIFICATION,
			 ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |
			 ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |
			 ACVP_DH_MODP_8192)

	DEVEL_KAS_IFC_SSC

	DEVEL_KAS_KDF_ONESTEP
	DEVEL_KAS_KDF_TWOSTEP

	DEVEL_RSA_DEC_PRIMITIVE10
	DEVEL_RSA_DEC_PRIMITIVE56Br2

	DEVEL_KDF_TPM

	DEVEL_COND_COMP

	DEVEL_KDF

	DEVEL_ANSI_X963

	DEVEL_AES_XTS

	DEVEL_TLS13_KDF

	DEVEL_XOF(ACVP_CSHAKE256)
	DEVEL_KMAC(ACVP_KMAC256)

	QCOM_HKDF

	NSS_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, ACVP_SHA256)

	ONESTEPNOCTR

	DEVEL_RSA_186_5

	LMS

	DEVEL_SLH_DSA
};

/**************************************************************************
 * Register operation
 **************************************************************************/
static struct def_algo_map devel_algo_map [] = {
	{
		SET_IMPLEMENTATION(devel),
		.algo_name = "Devel",
		.processor = "X86",
		.impl_name = "Generic C"
	}
};

ACVP_DEFINE_CONSTRUCTOR(devel_register)
static void devel_register(void)
{
	acvp_register_algo_map(devel_algo_map, ARRAY_SIZE(devel_algo_map));
}

ACVP_EXTENSION(devel_algo_map)
