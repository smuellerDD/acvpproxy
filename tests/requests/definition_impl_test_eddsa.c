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
 * EDDSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_eddsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};


#define TESTS_EDDSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_KEYGEN,	\
			DEF_PREREQS(tests_eddsa_prereqs),		\
			.curve = ACVP_ED25519,				\
			}						\
		}							\
	}

#define TESTS_EDDSA_KEYVER						\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_KEYVER,	\
			DEF_PREREQS(tests_eddsa_prereqs),		\
			.curve = ACVP_ED25519,				\
			}						\
		}							\
	}

#define TESTS_EDDSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGGEN,	\
			DEF_PREREQS(tests_eddsa_prereqs),		\
			.curve = ACVP_ED25519,				\
			.eddsa_pure = DEF_ALG_EDDSA_PURE_SUPPORTED,	\
			.eddsa_prehash = DEF_ALG_EDDSA_PREHASH_SUPPORTED,\
			}						\
		}							\
	}

#define TESTS_EDDSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_EDDSA,					\
	.algo = {							\
		.eddsa = {						\
			.eddsa_mode = DEF_ALG_EDDSA_MODE_SIGVER,	\
			DEF_PREREQS(tests_eddsa_prereqs),		\
			.curve = ACVP_ED25519,				\
			.eddsa_pure = DEF_ALG_EDDSA_PURE_SUPPORTED,	\
			.eddsa_prehash = DEF_ALG_EDDSA_PREHASH_SUPPORTED,\
			}						\
		}							\
	}


/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_EDDSA_KEYGEN,
	TESTS_EDDSA_KEYVER,
	TESTS_EDDSA_SIGGEN,
	TESTS_EDDSA_SIGVER,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "EDDSA"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
