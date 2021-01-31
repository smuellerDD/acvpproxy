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
 * DRBG Definitions
 **************************************************************************/
static const struct def_algo_prereqs aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
};

#define TESTS_DRBG_CAPS_AES128						\
	.mode = ACVP_AES128,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 512

#define TESTS_DRBG_CAPS_AES128_DF					\
	{								\
	TESTS_DRBG_CAPS_AES128,						\
	.entropyinputlen = { 128, },					\
	.noncelen = { 64 },						\
	.df = true							\
	}

#define TESTS_DRBG_CAPS_AES128_NODF					\
	{								\
	TESTS_DRBG_CAPS_AES128,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 64 },						\
	.df = false							\
	}

#define TESTS_DRBG_CAPS_AES192						\
	.mode = ACVP_AES192,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 1024

#define TESTS_DRBG_CAPS_AES192_DF					\
	{								\
	TESTS_DRBG_CAPS_AES192,						\
	.entropyinputlen = { 192, },					\
	.noncelen = { 128, },						\
	.df = true							\
	}

#define TESTS_DRBG_CAPS_AES192_NODF					\
	{								\
	TESTS_DRBG_CAPS_AES192,						\
	.entropyinputlen = { 320, },					\
	.noncelen = { 96, },						\
	.df = false							\
	}

#define TESTS_DRBG_CAPS_AES256						\
	.mode = ACVP_AES256,						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 512

#define TESTS_DRBG_CAPS_AES256_DF					\
	{								\
	TESTS_DRBG_CAPS_AES256,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 128, },						\
	.df = true							\
	}

#define TESTS_DRBG_CAPS_AES256_NODF					\
	{								\
	TESTS_DRBG_CAPS_AES256,						\
	.entropyinputlen = { 384, },					\
	.noncelen = { 128, },						\
	.df = false							\
	}

#define TESTS_DRBG_CTR							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "ctrDRBG",				\
			DEF_PREREQS(aes_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
			.capabilities = {				\
				TESTS_DRBG_CAPS_AES128_DF,		\
				TESTS_DRBG_CAPS_AES128_NODF,		\
				TESTS_DRBG_CAPS_AES192_DF,		\
				TESTS_DRBG_CAPS_AES192_NODF,		\
				TESTS_DRBG_CAPS_AES256_DF,		\
				TESTS_DRBG_CAPS_AES256_NODF },		\
			.num_caps = 6,					\
			}						\
		}							\
	}

static const struct def_algo_prereqs hmac_prereqs[] = {
	{
		.algorithm = "HMAC",
		.valvalue = "same"
	},
};

static const struct def_algo_prereqs sha_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
};

#define TESTS_DRBG_CAPS_SHA1						\
	{								\
	.mode = ACVP_SHA1,						\
	.entropyinputlen = { 160, },					\
	.noncelen = { 160, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 320,						\
	}

#define TESTS_DRBG_CAPS_SHA224						\
	{								\
	.mode = ACVP_SHA224,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 224,						\
	}

#define TESTS_DRBG_CAPS_SHA256						\
	{								\
	.mode = ACVP_SHA256,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 1024,					\
	}

#define TESTS_DRBG_CAPS_SHA384						\
	{								\
	.mode = ACVP_SHA384,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 384,						\
	}

#define TESTS_DRBG_CAPS_SHA512						\
	{								\
	.mode = ACVP_SHA512,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 2048,					\
	}

#define TESTS_DRBG_HMAC							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
			.capabilities = {				\
				TESTS_DRBG_CAPS_SHA1,			\
				TESTS_DRBG_CAPS_SHA224,			\
				TESTS_DRBG_CAPS_SHA256,			\
				TESTS_DRBG_CAPS_SHA384,			\
				TESTS_DRBG_CAPS_SHA512 },		\
			.num_caps = 5,					\
			}						\
		}							\
	}

#define TESTS_DRBG_HASH							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED |		\
			      DEF_ALG_DRBG_PR_ENABLED,			\
			.reseed = false,				\
			.capabilities = {				\
				TESTS_DRBG_CAPS_SHA1,			\
				TESTS_DRBG_CAPS_SHA224,			\
				TESTS_DRBG_CAPS_SHA256,			\
				TESTS_DRBG_CAPS_SHA384,			\
				TESTS_DRBG_CAPS_SHA512 },		\
			.num_caps = 5,					\
			}						\
		}							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_DRBG_CTR,
	TESTS_DRBG_HASH,
	TESTS_DRBG_HMAC,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "DRBG"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
