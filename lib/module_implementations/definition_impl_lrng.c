/* LRNG module definition
 *
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * AES Definitions
 **************************************************************************/
#define LRNG_AES_ECB		GENERIC_AES_ECB

/**************************************************************************
 * Hash Definition
 **************************************************************************/
#define LRNG_SHA(sha_def)	GENERIC_SHA(sha_def)
#define LRNG_HMAC(sha_def)	GENERIC_HMAC(sha_def)

/**************************************************************************
 * DRBG Definitions
 **************************************************************************/
static const struct def_algo_prereqs aes_prereqs[] = {
	{
		.algorithm = "AES",
		.valvalue = "same"
	},
};

#define LRNG_DRBG_CAPS_AES128						\
	{								\
	.mode = ACVP_AES128,						\
	.df = true,							\
	.entropyinputlen = { 128, },					\
	.noncelen = { 64, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 512,						\
	}

#define LRNG_DRBG_CAPS_AES192						\
	{								\
	.mode = ACVP_AES192,						\
	.df = true,							\
	.entropyinputlen = { 192, },					\
	.noncelen = { 128, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 1024,					\
	}

#define LRNG_DRBG_CAPS_AES256						\
	{								\
	.mode = ACVP_AES256,						\
	.df = true,							\
	.entropyinputlen = { 256, },					\
	.noncelen = { 128, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, },			\
	.returnedbitslen = 4096,					\
	}

#define LRNG_DRBG_CTR							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "ctrDRBG",				\
			DEF_PREREQS(aes_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED,			\
			.reseed = true,					\
			.capabilities = {				\
				LRNG_DRBG_CAPS_AES128,			\
				LRNG_DRBG_CAPS_AES192,			\
				LRNG_DRBG_CAPS_AES256 },		\
			.num_caps = 3,					\
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

#define LRNG_DRBG_CAPS_SHA1						\
	{								\
	.mode = ACVP_SHA1,						\
	.entropyinputlen = { 160, },					\
	.noncelen = { 160, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, 160, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 160, },		\
	.returnedbitslen = 320,						\
	}

#define LRNG_DRBG_CAPS_SHA256						\
	{								\
	.mode = ACVP_SHA256,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, 256, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 1024,					\
	}

#define LRNG_DRBG_CAPS_SHA384						\
	{								\
	.mode = ACVP_SHA384,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, 256, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 384,						\
	}

#define LRNG_DRBG_CAPS_SHA512						\
	{								\
	.mode = ACVP_SHA512,						\
	.entropyinputlen = { 256, },					\
	.noncelen = { 256, },						\
	.persostringlen = { DEF_ALG_ZERO_VALUE, 256, },			\
	.additionalinputlen = { DEF_ALG_ZERO_VALUE, 256, },		\
	.returnedbitslen = 2048,					\
	}

#define LRNG_DRBG_HMAC							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hmacDRBG",			\
			DEF_PREREQS(hmac_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED,			\
			.reseed = false,				\
			.capabilities = {				\
				LRNG_DRBG_CAPS_SHA1,			\
				LRNG_DRBG_CAPS_SHA256,			\
				LRNG_DRBG_CAPS_SHA384,			\
				LRNG_DRBG_CAPS_SHA512 },		\
			.num_caps = 4,					\
			}						\
		}							\
	}

#define LRNG_DRBG_HASH							\
	{								\
	.type = DEF_ALG_TYPE_DRBG,					\
	.algo = {							\
		.drbg = {						\
			.algorithm = "hashDRBG",			\
			DEF_PREREQS(sha_prereqs),			\
			.pr = DEF_ALG_DRBG_PR_DISABLED,			\
			.reseed = false,				\
			.capabilities = {				\
				LRNG_DRBG_CAPS_SHA1,			\
				LRNG_DRBG_CAPS_SHA256,			\
				LRNG_DRBG_CAPS_SHA384,			\
				LRNG_DRBG_CAPS_SHA512 },		\
			.num_caps = 4,					\
			}						\
		}							\
	}

/**************************************************************************
 * LRNG Definitions: hash used together with ChaCha20 DRNG
 **************************************************************************/
static const struct def_algo lrng_sha[] = {
	// NOTE: Enable the compiled hash type - see /proc/lrng_type

	LRNG_SHA(ACVP_SHA256),
	//LRNG_SHA(ACVP_SHA1),
};

/**************************************************************************
 * LRNG Definitions: hash used together with SP800-90A DRBG
 **************************************************************************/
static const struct def_algo lrng_kcapi[] = {
	LRNG_AES_ECB,

	LRNG_SHA(ACVP_SHA1),
	LRNG_SHA(ACVP_SHA256),
	LRNG_SHA(ACVP_SHA384),
	LRNG_SHA(ACVP_SHA512),

 	LRNG_HMAC(ACVP_HMACSHA1),
 	LRNG_HMAC(ACVP_HMACSHA2_256),
 	LRNG_HMAC(ACVP_HMACSHA2_384),
 	LRNG_HMAC(ACVP_HMACSHA2_512),

	LRNG_DRBG_CTR,
	LRNG_DRBG_HMAC,
	LRNG_DRBG_HASH,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map lrng_algo_map [] = {
	{
		SET_IMPLEMENTATION(lrng_sha),
		.algo_name = "Linux Random Number Generator",
		.processor = "",
		.impl_name = "LRNG implementation",
		.impl_description = "Implementation of SHA provided by LRNG",
	}, {
		SET_IMPLEMENTATION(lrng_kcapi),
		.algo_name = "Linux Random Number Generator",
		.processor = "",
		.impl_name = "Kernel Crypto API implementation",
		.impl_description = "Implementation of SHA provided by Linux Kernel Crypto API",
	}
};

ACVP_DEFINE_CONSTRUCTOR(lrng_register)
static void lrng_register(void)
{
	acvp_register_algo_map(lrng_algo_map, ARRAY_SIZE(lrng_algo_map));
}

ACVP_EXTENSION(lrng_algo_map)
