/*
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for EDDSA implementations. In
 * order to define a given EDDSA implementation, the following data structures
 * must be instantiated. The root of the data structures is
 * @struct def_algo_eddsa. Please start from this data structure and fill
 * in the required field for the requested type of EDDSA implementation.
 */

#ifndef DEFINITION_CIPHER_EDDSA_H
#define DEFINITION_CIPHER_EDDSA_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * EDDSA common data data
 ****************************************************************************/
struct def_algo_eddsa {
	/*
	 * EDDSA mode type
	 * required: always
	 */
	enum eddsa_mode {
		DEF_ALG_EDDSA_MODE_KEYGEN,
		DEF_ALG_EDDSA_MODE_KEYVER,
		DEF_ALG_EDDSA_MODE_SIGGEN,
		DEF_ALG_EDDSA_MODE_SIGVER,
	} eddsa_mode;

	/*
	 * Prerequisites to EDDSA
	 * required: always
	 * SHA
	 * SHA_OPT2
	 * SHA_OPT3
	 * DRBG
	 * DRBG_OPT2
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * One or more of the following:
	 * "ED-25519"
	 * "ED-448"
	 *
	 * required: always
	 */
	cipher_t curve;

	/*
	 * The method used to generate the randomness incorporated in the key.
	 * required: always for ECDSA keygen
	 */
#define DEF_ALG_EDDSA_EXTRA_BITS (1 << 0)
#define DEF_ALG_EDDSA_TESTING_CANDIDATES (1 << 1)
	unsigned int secretgenerationmode;

	/*
	 * If the IUT supports normal 'pure' sigGen functionality.
	 * required: always for EDDSA siggen and siggver
	 */
	enum eddsa_pure {
		DEF_ALG_EDDSA_PURE_SUPPORTED,
		DEF_ALG_EDDSA_PURE_UNSUPPORTED,
	} eddsa_pure;

	/*
	 * If the IUT supports accepting a preHashed message to sign.
	 * required: always for EDDSA siggen and siggver
	 */
	enum eddsa_prehash {
		DEF_ALG_EDDSA_PREHASH_SUPPORTED,
		DEF_ALG_EDDSA_PREHASH_UNSUPPORTED,
	} eddsa_prehash;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_EDDSA_H */
