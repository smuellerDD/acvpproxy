/* Jitter RNG module definition
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
#define JENT_SHA(sha_def)	GENERIC_SHA(sha_def)

/**************************************************************************
 * JENT Generic Definitions
 **************************************************************************/
static const struct def_algo jent[] = {
	JENT_SHA(ACVP_SHA3_256),
};

/**************************************************************************
 * Register operation
 **************************************************************************/

static struct def_algo_map jent_algo_map [] = {
	{
		SET_IMPLEMENTATION(jent),
		.algo_name = "Jitter RNG",
		.processor = "",
		.impl_name = "Generic C",
		.impl_description = "Generic C implementation of SHA",
	}
};

ACVP_DEFINE_CONSTRUCTOR(jent_register)
static void jent_register(void)
{
	acvp_register_algo_map(jent_algo_map,
			       ARRAY_SIZE(jent_algo_map));
}

ACVP_EXTENSION(jent_algo_map)
