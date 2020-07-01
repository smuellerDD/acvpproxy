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
 * Hash Definitions
 **************************************************************************/
#define TESTS_CMAC_AES						\
	GENERIC_CMAC_AES((DEF_ALG_SYM_KEYLEN_128 | DEF_ALG_SYM_KEYLEN_192 | \
			 DEF_ALG_SYM_KEYLEN_256))

#define TESTS_CMAC_TDES						\
	{								\
	.type = DEF_ALG_TYPE_CMAC,					\
	.algo = {							\
		.cmac = {						\
			.algorithm = ACVP_CMAC_TDES,			\
			.prereqvals = {					\
				.algorithm = "TDES",			\
				.valvalue = "same"			\
				},					\
			.direction = DEF_ALG_CMAC_GENERATION |		\
				     DEF_ALG_CMAC_VERIFICATION,		\
			.keylen = DEF_ALG_SYM_KEYLEN_168, 		\
			.msglen = { 64, 128, 72, 136, 524288 }		\
			}						\
		},							\
	}

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_CMAC_AES,
	TESTS_CMAC_TDES
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "CMAC"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
