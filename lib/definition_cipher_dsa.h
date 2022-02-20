/*
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

/**
 * This header file defines the required data for DSA implementations. In order
 * to define a given DSA implementation, the following data structures must be
 * instantiated. The root of the data structures is @struct def_algo_dsa.
 * Please start from this data structure and fill in the required field for the
 * requested type of DSA implementation.
 */

#ifndef DEFINITION_CIPHER_DSA_H
#define DEFINITION_CIPHER_DSA_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * DSA common data data
 ****************************************************************************/
struct def_algo_dsa {
	/*
	 * DSA mode type
	 * required: always
	 */
	enum dsa_mode {
		DEF_ALG_DSA_MODE_PQGGEN,
		DEF_ALG_DSA_MODE_PQGVER,
		DEF_ALG_DSA_MODE_KEYGEN,
		DEF_ALG_DSA_MODE_SIGGEN,
		DEF_ALG_DSA_MODE_SIGVER,
	} dsa_mode;

	/*
	 * Prerequisites to DSA
	 * required: always
	 * SHA
	 * DRBG
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * The length in bits of the field and the length in bits of prime p.
	 *
	 * required: always
	 */
	enum dsa_l {
		DEF_ALG_DSA_L_1024,
		DEF_ALG_DSA_L_2048,
		DEF_ALG_DSA_L_3072,
	} dsa_l;

	/*
	 * The length in bits of q which is a prime factor of (p-1).
	 *
	 * required: always
	 */
	enum dsa_n {
		DEF_ALG_DSA_N_160,
		DEF_ALG_DSA_N_224,
		DEF_ALG_DSA_N_256,
	} dsa_n;

	/*
	 * Supported hash supported when generating p, q and g.
	 *
	 * Note that the digest size of the hash function MUST be equal to or
	 * greater than N.
	 *
	 * Allowed values:
	 *	"SHA2-224"
	 *	"SHA2-256"
	 *	"SHA2-384"
	 *	"SHA2-512"
	 *	"SHA2-512/224"
	 *	"SHA2-512/256"
	 *
	 * required: always for PQG generation / verification, signature
	 * generation and verification
	 */
	cipher_t hashalg;

	/*
	 * The methods supported to generate p and q.
	 *
	 * required: PQG generation and verification
	 */
#define DEF_ALG_DSA_PROBABLE_PQ_GEN (1 << 0)
#define DEF_ALG_DSA_PROVABLE_PQ_GEN (1 << 1)
	unsigned int dsa_pq_gen_method;

	/*
	 * The methods supported to generate g
	 *
	 * required: PQG generation and verification
	 */
#define DEF_ALG_DSA_UNVERIFIABLE_G_GEN (1 << 0)
#define DEF_ALG_DSA_CANONICAL_G_GEN (1 << 1)
	unsigned int dsa_g_gen_method;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_DSA_H */
