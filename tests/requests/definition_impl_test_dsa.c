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
 * DSA Definitions
 **************************************************************************/

static const struct def_algo_prereqs tests_dsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define TESTS_DSA_PQG_COMMON(x, L, N, hashes)				\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = x,					\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(tests_dsa_prereqs),			\
			.dsa_pq_gen_method = DEF_ALG_DSA_PROBABLE_PQ_GEN, \
			.dsa_g_gen_method = DEF_ALG_DSA_UNVERIFIABLE_G_GEN, \
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define TESTS_DSA_PQGGEN(L, N, hashes)					\
		TESTS_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGGEN, L, N, hashes)
#define TESTS_DSA_PQGVER(L, N, hashes)					\
		TESTS_DSA_PQG_COMMON(DEF_ALG_DSA_MODE_PQGVER, L, N, hashes)

#define TESTS_DSA_KEYGEN(L, N)						\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_KEYGEN,		\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(tests_dsa_prereqs),			\
			}						\
		}							\
	}

#define TESTS_DSA_SIGGEN(L, N, hashes)					\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_SIGGEN,		\
			.dsa_l = L,					\
			.dsa_n = N,					\
			DEF_PREREQS(tests_dsa_prereqs),			\
			.hashalg = hashes,				\
			}						\
		}							\
	}

#define TESTS_DSA_SIGVER(L, N, hashes)					\
	{								\
	.type = DEF_ALG_TYPE_DSA,					\
	.algo = {							\
		.dsa = {						\
			.dsa_mode = DEF_ALG_DSA_MODE_SIGVER,		\
			.dsa_l = L,		 			\
			.dsa_n = N,					\
			DEF_PREREQS(tests_dsa_prereqs),			\
			.hashalg = hashes,				\
			}						\
		}							\
	}


/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224, ACVP_SHA224),
	TESTS_DSA_PQGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, ACVP_SHA256),
	TESTS_DSA_PQGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256, ACVP_SHA256),

	TESTS_DSA_PQGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160, ACVP_SHA1),
	TESTS_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224, ACVP_SHA224),
	TESTS_DSA_PQGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256, ACVP_SHA256),
	TESTS_DSA_PQGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256, ACVP_SHA256),

	TESTS_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224),
	TESTS_DSA_KEYGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256),
	TESTS_DSA_KEYGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256),

	TESTS_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,
			   ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	TESTS_DSA_SIGGEN(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),
	TESTS_DSA_SIGGEN(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,
			   ACVP_SHA256 | ACVP_SHA384 | ACVP_SHA512),

	TESTS_DSA_SIGVER(DEF_ALG_DSA_L_1024, DEF_ALG_DSA_N_160,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	TESTS_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_224,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	TESTS_DSA_SIGVER(DEF_ALG_DSA_L_2048, DEF_ALG_DSA_N_256,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
	TESTS_DSA_SIGVER(DEF_ALG_DSA_L_3072, DEF_ALG_DSA_N_256,
			   ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | ACVP_SHA384 |
			   ACVP_SHA512),
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "DSA"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
