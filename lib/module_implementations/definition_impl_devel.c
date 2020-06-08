/* Nettle module definition
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
#if 1
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
	.onestekdf = {
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
	.twostekdf = devel_kas_ffc_twostepkdf,
	.twostekdf_num = ARRAY_SIZE(devel_kas_ffc_twostepkdf),
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
	.onestekdf = {
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
	.twostekdf = devel_kas_ecc_twostepkdf,
	.twostekdf_num = ARRAY_SIZE(devel_kas_ecc_twostepkdf),
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
		DEF_PREREQS(devel_dh_r3_prereqs),			\
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

const struct def_algo_kas_ifc_keygen devel_kas_ifc_keygen[] = { {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG1_BASIC,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,
		        DEF_ALG_RSA_MODULO_8192, DEF_ALG_RSA_MODULO_2048 },
	.fixedpubexp = "010001",
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_8192, },
	.fixedpubexp = "010001",
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG1_CRT,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_6144, },
	.fixedpubexp = "010001",
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG1_CRT,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_4096, },
	.fixedpubexp = "010001",
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG2_BASIC,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_3072, }
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG2_PRIME_FACTOR,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_2048, }
}, {
	.keygen_method = DEF_ALG_KAS_IFC_RSAKPG2_CRT,
	.rsa_modulo = { DEF_ALG_RSA_MODULO_2048, }
} };

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
	.keygen = devel_kas_ifc_keygen,
	.keygen_num = ARRAY_SIZE(devel_kas_ifc_keygen),
	.onestekdf = {
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
	.twostekdf = devel_kas_ifc_twostepkdf,
	.twostekdf_num = ARRAY_SIZE(devel_kas_ifc_twostepkdf),
	.mac = devel_kas_ifc_mac,
	.mac_entries = ARRAY_SIZE(devel_kas_ifc_mac),
	.length = 1024,
} };

const struct def_algo_kas_ifc_schema devel_kas_ifc_schema_kts[] = { {
	.schema = DEF_ALG_KAS_IFC_KTS_OAEP_BASIC,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.keygen = devel_kas_ifc_keygen,
	.keygen_num = ARRAY_SIZE(devel_kas_ifc_keygen),
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
			    DEF_ALG_KAS_IFC_PARITALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.schema = devel_kas_ifc_schema_kas,			\
		.schema_num = ARRAY_SIZE(devel_kas_ifc_schema_kas),	\
		},							\
	},								\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(devel_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARITALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.schema = devel_kas_ifc_schema_kts,			\
		.schema_num = ARRAY_SIZE(devel_kas_ifc_schema_kts),	\
		},							\
	}
#else
#define DEVEL_KAS_IFC
#endif

/**************************************************************************
 * Nettle Implementation Definitions
 **************************************************************************/
static const struct def_algo devel[] = {
	DEVEL_KAS_FFC_R3
	DEVEL_KAS_ECC_R3
	DEVEL_KAS_IFC

	DEVEL_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYGENERATION,
			 ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |
			 ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |
			 ACVP_DH_MODP_8192),
	DEVEL_SAFEPRIMES(DEF_ALG_SAFEPRIMES_KEYVERIFICATION,
			 ACVP_DH_MODP_2048 | ACVP_DH_MODP_3072 |
			 ACVP_DH_MODP_4096 | ACVP_DH_MODP_6144 |
			 ACVP_DH_MODP_8192)
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
