/* ACVP Proxy hash and HMAC module definition
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * SP800-56A rev3 ECC SSC
 **************************************************************************/
#define TESTS_KAS_ECC_SSC_R3						\
 	GENERIC_KAS_ECC_SSC_R3(ACVP_NISTP256 | ACVP_NISTP384 | ACVP_NISTP521),\
 	GENERIC_KAS_ECC_SSC_R3_HASH(ACVP_NISTP256 | ACVP_NISTP384 |	\
				    ACVP_NISTP521, ACVP_SHA3_512)

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_KAS_ECC_SSC_R3,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "KAS-ECC-SSC-R3"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
