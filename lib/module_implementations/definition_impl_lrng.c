/* LRNG module definition
 *
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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
 * Hash Definition
 **************************************************************************/
#define LRNG_SHA(sha_def)	GENERIC_SHA(sha_def)

#define LRNG_HASHDF(sha_def, derived_len_def)				\
	{								\
	.type = DEF_ALG_TYPE_COND_COMP,					\
	.algo = {							\
		.cond_comp = {						\
			.mode = ACVP_COND_COMP_HASH_DF,			\
			.hashalg = sha_def,				\
			.derived_len[0] = derived_len_def,		\
			}						\
		},							\
	}

/**************************************************************************
 * LRNG Generic Definitions
 **************************************************************************/
static const struct def_algo lrng[] = {
	LRNG_SHA(ACVP_SHA256),
	LRNG_SHA(ACVP_SHA1),
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map lrng_algo_map [] = {
	{
		SET_IMPLEMENTATION(lrng),
		.algo_name = "Linux Random Number Generator",
		.processor = "",
		.impl_name = "Generic C",
		.impl_description = "Generic C implementation of SHA",
	}
};

ACVP_DEFINE_CONSTRUCTOR(lrng_register)
static void lrng_register(void)
{
	acvp_register_algo_map(lrng_algo_map,
			       ARRAY_SIZE(lrng_algo_map));
}

ACVP_EXTENSION(lrng_algo_map)
