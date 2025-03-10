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
 * Hash Definitions
 **************************************************************************/
#define TESTS_AES_ECB		GENERIC_AES_ECB
#define TESTS_AES_CBC		GENERIC_AES_CBC
#define TESTS_AES_CTR		GENERIC_AES_CTR
#define TESTS_AES_KW		GENERIC_AES_KW
#define TESTS_AES_KWP		GENERIC_AES_KWP
#define TESTS_AES_XTS		GENERIC_AES_XTS
#define TESTS_AES_OFB		GENERIC_AES_OFB
#define TESTS_AES_CFB1		GENERIC_AES_CFB1
#define TESTS_AES_CFB8		GENERIC_AES_CFB8
#define TESTS_AES_CFB128	GENERIC_AES_CFB128

/**************************************************************************
 * Tests Generic Definitions
 **************************************************************************/
static const struct def_algo tests[] = {
	TESTS_AES_ECB,
	TESTS_AES_CBC,
	TESTS_AES_CTR,
	TESTS_AES_KW,
	TESTS_AES_KWP,
	TESTS_AES_XTS,
	TESTS_AES_OFB,
	TESTS_AES_CFB1,
	TESTS_AES_CFB8,
	TESTS_AES_CFB128
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map tests_algo_map [] = {
	{
		SET_IMPLEMENTATION(tests),
		.algo_name = "Tests",
		.processor = "",
		.impl_name = "AES-SYM"
	}
};

ACVP_DEFINE_CONSTRUCTOR(tests_register)
static void tests_register(void)
{
	acvp_register_algo_map(tests_algo_map, ARRAY_SIZE(tests_algo_map));
}
