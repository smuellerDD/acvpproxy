/* ACVP Proxy hash and HMAC module definition
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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
 * SP800-108 KDF Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_kdf_hmac_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs tests_kdf_cmac_prereqs[] = {
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
#define TESTS_KDF_CMAC_AES_DEF(kdf_type, ctr_loc)			\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(tests_kdf_cmac_prereqs),			\
		.kdf_108_type = kdf_type,				\
		.macalg = ACVP_CMAC_AES128 | ACVP_CMAC_AES192 |		\
			  ACVP_CMAC_AES256,				\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = false				\
		}							\
	}

#define TESTS_KDF_CMAC_AES						\
	TESTS_KDF_CMAC_AES_DEF(DEF_ALG_KDF_108_COUNTER,			\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_CMAC_AES_DEF(DEF_ALG_KDF_108_FEEDBACK,		\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_CMAC_AES_DEF(DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA)

#define TESTS_KDF_CMAC_TDES_DEF(kdf_type, ctr_loc)			\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(tests_kdf_cmac_prereqs),			\
		.kdf_108_type = kdf_type,				\
		.macalg =  ACVP_CMAC_TDES,				\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = false				\
		}							\
	}

#define TESTS_KDF_CMAC_TDES						\
	TESTS_KDF_CMAC_TDES_DEF(DEF_ALG_KDF_108_COUNTER,		\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_CMAC_TDES_DEF(DEF_ALG_KDF_108_FEEDBACK,		\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_CMAC_TDES_DEF(DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,\
			       DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA)

#define TESTS_KDF_HMAC_DEF(kdf_type, ctr_loc)				\
	{								\
	.type = DEF_ALG_TYPE_KDF_108,					\
	.algo.kdf_108 = {						\
		DEF_PREREQS(tests_kdf_hmac_prereqs),			\
		.kdf_108_type = kdf_type,				\
		.macalg = ACVP_HMACSHA1 | ACVP_HMACSHA2_224 |		\
			  ACVP_HMACSHA2_256 | ACVP_HMACSHA2_384 |	\
			  ACVP_HMACSHA2_512,				\
		.supported_lengths = { 8, 72, 128, 776, 3456, 4096 },	\
		.fixed_data_order = ctr_loc,				\
		.counter_lengths = DEF_ALG_KDF_108_COUNTER_LENGTH_32,	\
		.supports_empty_iv = false				\
		}							\
	}

#define TESTS_KDF_HMAC							\
	TESTS_KDF_HMAC_DEF(DEF_ALG_KDF_108_COUNTER,			\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_HMAC_DEF(DEF_ALG_KDF_108_FEEDBACK,			\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA),\
	TESTS_KDF_HMAC_DEF(DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,\
			      DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA)

/**************************************************************************
 * TLS Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_kdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define TESTS_TLS							\
	{								\
	.type = DEF_ALG_TYPE_KDF_TLS,					\
	.algo.kdf_tls = {						\
		DEF_PREREQS(tests_kdf_prereqs),				\
		.tls_version = DEF_ALG_KDF_TLS_1_0_1_1 |		\
			       DEF_ALG_KDF_TLS_1_2,			\
		.hashalg = ACVP_SHA256 | ACVP_SHA384			\
		}							\
	}

/**************************************************************************
 * IKEv2 Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_ikekdf_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define TESTS_KDF_IKEV1_HASH(hash)					\
	{								\
	.type = DEF_ALG_TYPE_KDF_IKEV1,					\
	.algo.kdf_ikev1 = {						\
		DEF_PREREQS(tests_ikekdf_prereqs),			\
		.authentication_method = DEF_ALG_KDF_IKEV1_DSA | 	\
					 DEF_ALG_KDF_IKEV1_PSK,		\
		.initiator_nonce_length = { 128, 256, 512, 2048 },	\
		.responder_nonce_length = { 128, 256, 512, 2048 },	\
		.diffie_hellman_shared_secret_length = { 224, 2048, 8192 }, \
		.pre_shared_key_length = { 8, 384, 768, 8192 },		\
		.hashalg = hash						\
		}							\
	}

#define TESTS_KDF_IKEV1							\
	TESTS_KDF_IKEV1_HASH(ACVP_SHA1),				\
	TESTS_KDF_IKEV1_HASH(ACVP_SHA256),				\
	TESTS_KDF_IKEV1_HASH(ACVP_SHA384),				\
	TESTS_KDF_IKEV1_HASH(ACVP_SHA512)

#define TESTS_KDF_IKEV2_HASH(hash)					\
	{								\
	.type = DEF_ALG_TYPE_KDF_IKEV2,					\
	.algo.kdf_ikev2 = {						\
		DEF_PREREQS(tests_ikekdf_prereqs),			\
		.initiator_nonce_length = { 128, 256, 512, 2048 },	\
		.responder_nonce_length = { 128, 256, 512, 2048 },	\
		.diffie_hellman_shared_secret_length = { 224, 2048, 8192 },\
		.derived_keying_material_length = { 1056, 3072 },	\
		.hashalg = hash,					\
		}							\
	}

#define TESTS_KDF_IKEV2							\
	TESTS_KDF_IKEV2_HASH(ACVP_SHA1),				\
	TESTS_KDF_IKEV2_HASH(ACVP_SHA256),				\
	TESTS_KDF_IKEV2_HASH(ACVP_SHA384),				\
	TESTS_KDF_IKEV2_HASH(ACVP_SHA512)

/**************************************************************************
 * SSH Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_sshaeskdf_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs tests_sshtdeskdf_prereqs[] = {
	{
		.algorithm = "TDES",
		.valvalue = "same"
	},
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define TESTS_SSH_KDF_AES						\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(tests_sshaeskdf_prereqs),			\
		.cipher = ACVP_AES128 | ACVP_AES192 | ACVP_AES256,	\
		.hashalg = ACVP_SHA1 | ACVP_SHA256 |			\
			   ACVP_SHA384 | ACVP_SHA512			\
		}							\
	}

#define TESTS_SSH_KDF_TDES						\
	{								\
	.type = DEF_ALG_TYPE_KDF_SSH,					\
	.algo.kdf_ssh = {						\
		DEF_PREREQS(tests_sshtdeskdf_prereqs),			\
		.cipher = ACVP_TDES,					\
		.hashalg = ACVP_SHA1 | ACVP_SHA256 |			\
			   ACVP_SHA384 | ACVP_SHA512			\
		}							\
	}

#define TESTS_SSH_KDF							\
	TESTS_SSH_KDF_AES,						\
	TESTS_SSH_KDF_TDES

/**************************************************************************
 * SP800-132 PBKDF Definitions
 **************************************************************************/
#define TESTS_PBKDF(x)	GENERIC_PBKDF(x)

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_TLS,

	TESTS_KDF_HMAC,
	TESTS_KDF_CMAC_TDES,
	TESTS_KDF_CMAC_AES,

	TESTS_KDF_IKEV1,
	TESTS_KDF_IKEV2,

	TESTS_SSH_KDF,

	TESTS_PBKDF(ACVP_SHA1 |
		    ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512 |
		    ACVP_SHA3_224 | ACVP_SHA3_256 | ACVP_SHA3_384 |
		    ACVP_SHA3_512),
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "KDF"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
