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

/**
 * This header file defines the required data for ECDSA implementations. In
 * order to define a given ECDSA implementation, the following data structures
 * must be instantiated. The root of the data structures is
 * @struct def_algo_ecdsa. Please start from this data structure and fill
 * in the required field for the requested type of ECDSA implementation.
 */

#ifndef DEFINITION_CIPHER_ECDSA_H
#define DEFINITION_CIPHER_ECDSA_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * ECDSA common data data
 ****************************************************************************/
struct def_algo_ecdsa {

	/*
	 * ECDSA mode type
	 * required: always
	 */
	enum ecdsa_mode {
		DEF_ALG_ECDSA_MODE_KEYGEN,
		DEF_ALG_ECDSA_MODE_KEYVER,
		DEF_ALG_ECDSA_MODE_SIGGEN,
		DEF_ALG_ECDSA_MODE_SIGVER,
	} ecdsa_mode;

	/*
	 * Prerequisites to ECDSA
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
	 * One or more of the following:
	 * "P-224"
	 * "P-256"
	 * "P-384"
	 * "P-521"
	 * "B-233"
	 * "B-283"
	 * "B-409"
	 * "B-571"
	 * "K-233"
	 * "K-283"
	 * "K-409"
	 * "K-571"
	 *
	 * required: always
	 */
	cipher_t curve;

	/*
	 * The method used to generate the randomness incorporated in the key.
	 * required: always for ECDSA keygen
	 */
#define DEF_ALG_ECDSA_EXTRA_BITS		(1<<0)
#define DEF_ALG_ECDSA_TESTING_CANDIDATES	(1<<1)
	unsigned int secretgenerationmode;

	/*
	 * One or more of the following:
	 * "SHA2-224"
	 * "SHA2-256"
	 * "SHA2-384"
	 * "SHA2-512"
	 * "SHA2-512/224"
	 * "SHA2-512/256"
	 *
	 * required: always for ECDSA siggen and sigver
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ECDSA_H */
