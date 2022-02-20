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
 * Hash Definitions
 **************************************************************************/
#define ACVPPROXY_SHA(x)	GENERIC_SHA(x)
#define ACVPPROXY_HMAC(x)	GENERIC_HMAC(x)

/**************************************************************************
 * ACVPProxy Generic Definitions
 **************************************************************************/
static const struct def_algo acvpproxy[] = {
	ACVPPROXY_SHA(ACVP_SHA256),
	ACVPPROXY_SHA(ACVP_SHA512),

	ACVPPROXY_SHA(ACVP_SHA3_224),
	ACVPPROXY_SHA(ACVP_SHA3_256),
	ACVPPROXY_SHA(ACVP_SHA3_384),
	ACVPPROXY_SHA(ACVP_SHA3_512),

	ACVPPROXY_HMAC(ACVP_HMACSHA2_256),
	ACVPPROXY_HMAC(ACVP_HMACSHA2_512),

	ACVPPROXY_HMAC(ACVP_HMACSHA3_224),
	ACVPPROXY_HMAC(ACVP_HMACSHA3_256),
	ACVPPROXY_HMAC(ACVP_HMACSHA3_384),
	ACVPPROXY_HMAC(ACVP_HMACSHA3_512)
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map acvpproxy_algo_map [] = {
	{
		SET_IMPLEMENTATION(acvpproxy),
		.algo_name = "Crypto for ACVPProxy",
		.processor = "",
		.impl_name = "Generic C",
		.impl_description = "Generic C implementation of SHA and HMAC",
	}
};

ACVP_DEFINE_CONSTRUCTOR(acvpproxy_register)
static void acvpproxy_register(void)
{
	acvp_register_algo_map(acvpproxy_algo_map,
			       ARRAY_SIZE(acvpproxy_algo_map));
}

ACVP_EXTENSION(acvpproxy_algo_map)
