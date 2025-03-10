/* Nettle module definition
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
 * SP800-56C rev 1 Twostep KDF
 **************************************************************************/
static const struct def_algo_prereqs tests_kdf_twostep_prereqs[] = {
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

const struct def_algo_kas_kdf_twostepkdf tests_kdf_twostepkdf[] = { {
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

#define TESTS_KAS_KDF_TWOSTEP						\
	{								\
	.type = DEF_ALG_TYPE_KDF_TWOSTEP,				\
	.algo.kdf_twostep = {						\
		DEF_PREREQS(tests_kdf_twostep_prereqs),			\
		.twostep = tests_kdf_twostepkdf,			\
		.twostep_num = ARRAY_SIZE(tests_kdf_twostepkdf),	\
		.length = 1024,						\
		DEF_ALG_DOMAIN(.zlen, 256, 512, 128),			\
		},							\
	}

/**************************************************************************
 * Implementation Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_KAS_KDF_TWOSTEP
};

/**************************************************************************
 * Register operation
 **************************************************************************/
static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "Twostep"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}

ACVP_EXTENSION(tests_algo_map)
