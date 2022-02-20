/* Nettle module definition
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
 * AES Definitions
 **************************************************************************/
#define NETTLE_AES_ECB	GENERIC_AES_ECB

/**************************************************************************
 * Nettle Implementation Definitions
 **************************************************************************/
static const struct def_algo nettle[] = {
	NETTLE_AES_ECB,
};

/**************************************************************************
 * Register operation
 **************************************************************************/
static struct def_algo_map nettle_algo_map [] = {
	{
		SET_IMPLEMENTATION(nettle),
		.algo_name = "Nettle",
		.processor = "",
		.impl_name = "Generic C",
		.impl_description = "Generic C implementation of AES",
	}
};

ACVP_DEFINE_CONSTRUCTOR(nettle_register)
static void nettle_register(void)
{
	acvp_register_algo_map(nettle_algo_map, ARRAY_SIZE(nettle_algo_map));
}

ACVP_EXTENSION(nettle_algo_map)
