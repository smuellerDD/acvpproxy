/* ACVP Proxy hash and HMAC module definition
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
 * SP800-56B rev2
 **************************************************************************/
static const struct def_algo_prereqs tests_kas_ifc_prereqs[] = {
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

const struct def_algo_kas_kdf_onestepkdf_aux tests_kas_ifc_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };

const struct def_algo_kas_kdf_twostepkdf tests_kas_ifc_twostepkdf[] = { {
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

const struct def_algo_kas_mac_method tests_kas_ifc_mac[] = { {
	.mac = ACVP_HMACSHA2_256,
	.key_length = 128,
	.mac_length = 128,
}, {
	.mac = ACVP_HMACSHA2_512,
	.key_length = 128,
	.mac_length = 128,
} };

const struct def_algo_kas_ifc_schema tests_kas_ifc_schema_kas[] = { {
	.schema = DEF_ALG_KAS_IFC_KAS1_PARTY_V,
	.kas_ifc_role = DEF_ALG_KAS_IFC_INITIATOR |
			DEF_ALG_KAS_IFC_RESPONDER,
	.onestekdf = {
		.aux_function = tests_kas_ifc_onestepkdf_aux,
		.aux_function_num = ARRAY_SIZE(tests_kas_ifc_onestepkdf_aux),
		.fixed_info_pattern_type = {
			DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
			DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
		.literal = "affedeadbeef",
		.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.twostepkdf = tests_kas_ifc_twostepkdf,
	.twostepkdf_num = ARRAY_SIZE(tests_kas_ifc_twostepkdf),
	.mac = tests_kas_ifc_mac,
	.mac_entries = ARRAY_SIZE(tests_kas_ifc_mac),
	.length = 1024,
} };

const struct def_algo_kas_ifc_schema tests_kas_ifc_schema_kts[] = { {
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
	.mac = tests_kas_ifc_mac,
	.mac_entries = ARRAY_SIZE(tests_kas_ifc_mac),
	.length = 1024,
} };

#define TESTS_KAS_IFC							\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(tests_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARITALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
				DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,	\
				DEF_ALG_KAS_IFC_RSAKPG1_CRT },		\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,		\
				DEF_ALG_RSA_MODULO_8192,		\
				DEF_ALG_RSA_MODULO_2048 },		\
		.keygen.fixedpubexp = "010001",				\
		.schema = tests_kas_ifc_schema_kas,			\
		.schema_num = ARRAY_SIZE(tests_kas_ifc_schema_kas),	\
		},							\
	},								\
	{								\
	.type = DEF_ALG_TYPE_KAS_IFC,					\
	.algo.kas_ifc = {						\
		DEF_PREREQS(tests_kas_ifc_prereqs),			\
		.function = DEF_ALG_KAS_IFC_KEYPAIRGEN |		\
			    DEF_ALG_KAS_IFC_PARITALVAL,			\
		.iut_identifier = "0123456789abcdef",			\
		.keygen.keygen_method = { DEF_ALG_KAS_IFC_RSAKPG1_BASIC,\
				DEF_ALG_KAS_IFC_RSAKPG1_PRIME_FACTOR,	\
				DEF_ALG_KAS_IFC_RSAKPG1_CRT },		\
		.keygen.rsa_modulo = { DEF_ALG_RSA_MODULO_6144,		\
				DEF_ALG_RSA_MODULO_8192,		\
				DEF_ALG_RSA_MODULO_2048 },		\
		.keygen.fixedpubexp = "010001",				\
		.schema = tests_kas_ifc_schema_kts,			\
		.schema_num = ARRAY_SIZE(tests_kas_ifc_schema_kts),	\
		},							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_KAS_IFC,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "KAS-IFC"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
