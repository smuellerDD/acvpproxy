/*
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

#ifndef DEFINITION_COMMON_H
#define DEFINITION_COMMON_H

#include <limits.h>

#include "bool.h"
#include "cipher_definitions.h"

#ifdef __cplusplus
extern "C" {
#endif

/* If an integer has to be set to a zero value, use this definition */
#define DEF_ALG_ZERO_VALUE ((1 << 30) - 1)

/* Maximum number of integer-based entries */
#define DEF_ALG_MAX_INT 12

/*
 * Domain definition
 *
 * Commonly we have DEF_ALG_MAX_INT integers allowing the specification of up
 * to that number of individual integers. However, ACVP allows to specify
 * either a given number of integers or a range denominated by a
 * min/max/increment definition. We reuse the DEF_ALG_MAX_INT integer
 * specification to also allow the specification of a range. To identify whether
 * a range is set, the first integer must have the DEF_ALG_RANGE_TYPE bit set
 * to mark the set of integers to denominate a range. If a range is defined,
 * the first integer specifies the min, the second the max and the third the
 * increment.
 */

/* Flag indicating the presence of a domain configuration */
#define DEF_ALG_RANGE_TYPE (1 << 30)
static inline int acvp_range_min_val(const int variable[])
{
	return (variable[0] & ~DEF_ALG_RANGE_TYPE);
}

#define DEF_ALG_DOMAIN(variable, min, max, inc)                                \
	variable[0] = (min | DEF_ALG_RANGE_TYPE), variable[1] = max,           \
	variable[2] = inc

#define DEF_PREREQS(x) .prereqvals = x, .prereqvals_num = ARRAY_SIZE(x)

/**
 * @brief Define a prerequisite for a cipher.
 *
 * @var algorithm Specify the algorithm name covered by this prerequisite.
 * @var valvalue Specify the validation reference.
 */
struct def_algo_prereqs {
	/*
	 * Valid values:
	 * AES
	 * DRBG
	 * SHA
	 * HMAC
	 * TDES
	 */
	const char *algorithm;

	/*
	 * Valid values:
	 * actual CAVS cert number
	 * "same" in case the dependency is fulfilled with current CAVS test
	 */
	const char *valvalue;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_COMMON_H */
