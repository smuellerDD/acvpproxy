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
 * ECDH Definitions
 **************************************************************************/
static const struct def_algo_prereqs tests_ecdh_prereqs[] = {
	{
		.algorithm = "SHA",
		.valvalue = "same"
	},
	{
		.algorithm = "DRBG",
		.valvalue = "same"
	},
};

static const struct def_algo_kas_ecc_nokdfnokc tests_kas_ecc_nokdfnokc_ec = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_EC,
	.curve = ACVP_NISTP256,
	.hashalg = ACVP_SHA256
};

static const struct def_algo_kas_ecc_nokdfnokc tests_kas_ecc_nokdfnokc_ed = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_ED,
	.curve = ACVP_NISTP384,
	.hashalg = ACVP_SHA384
};

static const struct def_algo_kas_ecc_nokdfnokc tests_kas_ecc_nokdfnokc_ee = {
	.kas_ecc_paramset = DEF_ALG_KAS_ECC_EE,
	.curve = ACVP_NISTP521,
	.hashalg = ACVP_SHA512
};

#define __TESTS_KAS_ECC(paramset)					\
	{								\
	.type = DEF_ALG_TYPE_KAS_ECC,					\
	.algo.kas_ecc = {						\
		DEF_PREREQS(tests_ecdh_prereqs),			\
		.kas_ecc_function = DEF_ALG_KAS_ECC_PARTIALVAL,		\
		.kas_ecc_schema = DEF_ALG_KAS_ECC_EPHEMERAL_UNIFIED,	\
		.kas_ecc_role = DEF_ALG_KAS_ECC_INITIATOR |		\
				DEF_ALG_KAS_ECC_RESPONDER,		\
		.kas_ecc_dh_type = DEF_ALG_KAS_ECC_NO_KDF_NO_KC,	\
		.type_info.nokdfnokc = paramset,			\
		},							\
	}

#define TESTS_KAS_ECC							\
	__TESTS_KAS_ECC(&tests_kas_ecc_nokdfnokc_ec),			\
	__TESTS_KAS_ECC(&tests_kas_ecc_nokdfnokc_ed),			\
	__TESTS_KAS_ECC(&tests_kas_ecc_nokdfnokc_ee)

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_KAS_ECC,
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "KAS-ECC"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
