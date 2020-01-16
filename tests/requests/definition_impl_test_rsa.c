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
 * RSA Definitions
 **************************************************************************/

static const struct def_algo_prereqs tests_rsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define TESTS_RSA_KEYGEN_CAPS_COMMON					\
	.rsa_primetest = DEF_ALG_RSA_PRIMETEST_C2,

static const struct def_algo_rsa_keygen_caps tests_rsa_keygen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	TESTS_RSA_KEYGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	TESTS_RSA_KEYGEN_CAPS_COMMON
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	TESTS_RSA_KEYGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_keygen tests_rsa_keygen = {
	.rsa_randpq = DEF_ALG_RSA_PQ_B33_PRIMES,
	.capabilities = tests_rsa_keygen_caps,
	.capabilities_num = ARRAY_SIZE(tests_rsa_keygen_caps),
};

static const struct def_algo_rsa_keygen_gen tests_rsa_keygen_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
	.keyformat = DEF_ALG_RSA_KEYFORMAT_STANDARD,
};

#define TESTS_RSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_KEYGEN,		\
			DEF_PREREQS(tests_rsa_prereqs),			\
			.gen_info.keygen = &tests_rsa_keygen_gen,	\
			.algspecs.keygen = &tests_rsa_keygen,		\
			.algspecs_num = 1,				\
			}						\
		}							\
	}

#define TESTS_RSA_SIGGEN_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512

static const struct def_algo_rsa_siggen_caps tests_rsa_siggen_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	TESTS_RSA_SIGGEN_CAPS_COMMON
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	TESTS_RSA_SIGGEN_CAPS_COMMON
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	TESTS_RSA_SIGGEN_CAPS_COMMON
} };

static const struct def_algo_rsa_siggen tests_rsa_siggen[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = tests_rsa_siggen_caps,
	.capabilities_num = ARRAY_SIZE(tests_rsa_siggen_caps),
} };

#define TESTS_RSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGGEN,		\
			DEF_PREREQS(tests_rsa_prereqs),			\
			.algspecs.siggen = tests_rsa_siggen,		\
			.algspecs_num = ARRAY_SIZE(tests_rsa_siggen),	\
			}						\
		}							\
	}

#define TESTS_RSA_SIGVER_CAPS_COMMON					\
	.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |\
		   ACVP_SHA512

static const struct def_algo_rsa_sigver_caps tests_rsa_sigver_caps[] = { {
	.rsa_modulo = DEF_ALG_RSA_MODULO_2048,
	TESTS_RSA_SIGVER_CAPS_COMMON,
}, {
	.rsa_modulo = DEF_ALG_RSA_MODULO_3072,
	TESTS_RSA_SIGVER_CAPS_COMMON,
// TODO reenable after https://github.com/usnistgov/ACVP/issues/273 is fixed
//}, {
//	.rsa_modulo = DEF_ALG_RSA_MODULO_4096,
//	TESTS_RSA_SIGVER_CAPS_COMMON,
} };

static const struct def_algo_rsa_sigver tests_rsa_sigver[] = { {
	.sigtype = DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	.capabilities = tests_rsa_sigver_caps,
	.capabilities_num = ARRAY_SIZE(tests_rsa_sigver_caps),
} };

static const struct def_algo_rsa_sigver_gen tests_rsa_sigver_gen = {
	.pubexpmode = DEF_ALG_RSA_PUBEXTMODE_RANDOM,
};

#define TESTS_RSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_RSA,					\
	.algo = {							\
		.rsa = {						\
			.rsa_mode = DEF_ALG_RSA_MODE_SIGVER,		\
			DEF_PREREQS(tests_rsa_prereqs),			\
			.gen_info.sigver = &tests_rsa_sigver_gen,	\
			.algspecs.sigver = tests_rsa_sigver,		\
			.algspecs_num = ARRAY_SIZE(tests_rsa_sigver),	\
			}						\
		}							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_RSA_KEYGEN,
	TESTS_RSA_SIGGEN,
	TESTS_RSA_SIGVER,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "RSA"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
