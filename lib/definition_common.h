/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

#include "acvpproxy.h"
#include "cipher_definitions.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* If an integer has to be set to a zero value, use this definition */
#define DEF_ALG_ZERO_VALUE	INT_MAX

/* Maximum number of integer-based entries */
#define DEF_ALG_MAX_INT		10

/**
 * @brief Define a range of values.
 *
 * @param min Minimum value of the range.
 * @param max Maximum value of the range
 * @param increment The stepping value of the parameters.
 */
struct def_algo_range {
	unsigned int min;
	unsigned int max;
	unsigned int increment;
};

#define DEF_PREREQS(x)					\
	.prereqvals = x,				\
	.prereqvals_num = ARRAY_SIZE(x)

/**
 * @brief Define a prerequisite for a cipher.
 *
 * @param algorithm Specify the algorithm name covered by this prerequisite.
 * @param valvalue Specify the validation reference.
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
