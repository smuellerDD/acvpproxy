/* ACVP Proxy hash and HMAC module definition
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
 * SP800-56A rev3 ECC
 **************************************************************************/
static const struct def_algo_prereqs tests_ecdh_r3_prereqs[] = {
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

const struct def_algo_kas_kdf_onestepkdf_aux tests_kas_ecc_onestepkdf_aux[] = { {
	.auxfunc = ACVP_HMACSHA2_256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_DEFAULT |
			   DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
}, {
	.auxfunc = ACVP_SHA256,
	.mac_salt_method = DEF_ALG_KAS_KDF_MAC_SALT_RANDOM
} };

const struct def_algo_kas_kdf_twostepkdf tests_kas_ecc_twostepkdf[] = { {
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

const struct def_algo_kas_mac_method tests_ecc_r3_mac[] = { {
	.mac = ACVP_HMACSHA2_256,
	.key_length = 128,
	.mac_length = 128,
}, {
	.mac = ACVP_HMACSHA2_512,
	.key_length = 128,
	.mac_length = 128,
} };

const struct def_algo_kas_ecc_r3_schema tests_ecc_r3_schema[] = { {
	.schema = DEF_ALG_KAS_ECC_R3_FULL_UNIFIED,
	.kas_ecc_role = DEF_ALG_KAS_ECC_R3_INITIATOR |
			DEF_ALG_KAS_ECC_R3_RESPONDER,
	.onestepkdf = {
			.aux_function = tests_kas_ecc_onestepkdf_aux,
			.aux_function_num = ARRAY_SIZE(tests_kas_ecc_onestepkdf_aux),
			.fixed_info_pattern_type = {
				DEF_ALG_KAS_KDF_FI_PATTERN_U_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_V_PARTY_INFO,
				DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL
			},
			.literal = "affedeadbeef",
			.fixed_info_encoding = DEF_ALG_KAS_KDF_FI_ENCODING_CONCATENATION,
		},
	.twostepkdf = tests_kas_ecc_twostepkdf,
	.twostepkdf_num = ARRAY_SIZE(tests_kas_ecc_twostepkdf),
	.key_confirmation_method = {
		.kc_direction = DEF_ALG_KAS_R3_UNILATERAL |
				DEF_ALG_KAS_R3_BILATERAL,
		.kcrole = DEF_ALG_KAS_R3_PROVIDER |
			  DEF_ALG_KAS_R3_RECIPIENT,
		.mac = tests_ecc_r3_mac,
		.mac_entries = ARRAY_SIZE(tests_ecc_r3_mac),
		},
	.length = 1024,
} };

#define TESTS_KAS_ECC_R3						\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC_R3,				\
	.algo.kas_ecc_r3 = {						\
		DEF_PREREQS(tests_ecdh_r3_prereqs),			\
		.kas_ecc_function = DEF_ALG_KAS_ECC_R3_KEYPAIRGEN |	\
				    DEF_ALG_KAS_ECC_R3_PARTIALVAL |	\
				    DEF_ALG_KAS_ECC_R3_FULLVAL,		\
		.iut_identifier = "1234567890abcdef",			\
		.schema = tests_ecc_r3_schema,				\
		.schema_num = ARRAY_SIZE(tests_ecc_r3_schema),		\
		.domain_parameter = ACVP_NISTP256 | ACVP_NISTP384 |	\
				    ACVP_NISTP521,			\
		},							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_KAS_ECC_R3,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "KAS-ECC-R3"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
