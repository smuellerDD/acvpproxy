/* ACVP Proxy hash and HMAC module definition
 *
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
 * ECDSA Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_ecdsa_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

#define TESTS_ECDSA_KEYGEN						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYGEN,	\
			DEF_PREREQS(tests_ecdsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			.secretgenerationmode = DEF_ALG_ECDSA_TESTING_CANDIDATES \
			}						\
		}							\
	}

#define TESTS_ECDSA_KEYVER						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_KEYVER,	\
			DEF_PREREQS(tests_ecdsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			}						\
		}							\
	}

#define TESTS_ECDSA_SIGGEN						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGGEN,	\
			DEF_PREREQS(tests_ecdsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			.hashalg = ACVP_SHA224 | ACVP_SHA256 |		\
				   ACVP_SHA384 | ACVP_SHA512,		\
			}						\
		}							\
	}

#define TESTS_ECDSA_SIGVER						\
	{								\
	.type = DEF_ALG_TYPE_ECDSA,					\
	.algo = {							\
		.ecdsa = {						\
			.ecdsa_mode = DEF_ALG_ECDSA_MODE_SIGVER,	\
			DEF_PREREQS(tests_ecdsa_prereqs),		\
			.curve = ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521,\
			.hashalg = ACVP_SHA1 | ACVP_SHA224 | ACVP_SHA256 | \
				   ACVP_SHA384 | ACVP_SHA512,		\
			}						\
		}							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_ECDSA_KEYGEN,
	TESTS_ECDSA_KEYVER,
	TESTS_ECDSA_SIGGEN,
	TESTS_ECDSA_SIGVER,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "ECDSA"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
