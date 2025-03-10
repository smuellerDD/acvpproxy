/*
 * Copyright (C) 2019 - 2025, Stephan Mueller <smueller@chronox.de>
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

/**
 * This header file defines the required data for SP800-132 PBKDF ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structures is @struct def_algo_pbkdf.
 */

#ifndef DEFINITION_CIPHER_PBKDF_H
#define DEFINITION_CIPHER_PBKDF_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-132 PBKDF
 ****************************************************************************/
struct def_algo_pbkdf {
	/*
	 * Prerequisites to KDF SP 800-108
	 * required: always
	 * SHA
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * The Hash used in the KDF.
	 *
	 * Add one or more of the following by ORing
	 * ACVP_SHA1
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 * ACVP_SHA512224
	 * ACVP_SHA512256
	 * ACVP_SHA3_224
	 * ACVP_SHA3_256
	 * ACVP_SHA3_384
	 * ACVP_SHA3_512
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * The number of hash iterations to be performed by the IUT.
	 *
	 * Minimum must be greater or equal to TODO. Maximum must be less than
	 * or equal to TODO.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int iteration_count[DEF_ALG_MAX_INT];

	/*
	 * The length of the output key in bits.
	 *
	 * Minimum must be greater or equal to TODO. Maximum must be less than
	 * or equal to TODO.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int keylen[DEF_ALG_MAX_INT];

	/*
	 * The length of the password used as input to the PBKDF in bytes
	 * (characters).
	 *
	 * Minimum must be greater or equal to TODO. Maximum must be less than
	 * or equal to TODO.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int passwordlen[DEF_ALG_MAX_INT];

	/*
	 * The length of the salt in bits.
	 *
	 * Minimum must be greater or equal to TODO. Maximum must be less than
	 * or equal to TODO.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int saltlen[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_PBKDF_H */
