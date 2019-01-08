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
 * This header file defines the required data for SP800-90A DRBGs. In order to
 * define a given DRBG implementation, the following data structures must
 * be instantiated. The root of the data structures is @struct def_algo_drbg.
 * Please start from this data structure and fill in the required field for the
 * requested type of DRBG implementation.
 */

#ifndef DEFINITION_DRBG_H
#define DEFINITION_DRBG_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct def_algo_drbg_caps {
	/*
	 * Hash DRBG:
	 *	SHA-1
	 *	SHA2-224
	 *	SHA2-256
	 *	SHA2-384
	 *	SHA2-512
	 *	SHA2-512/224
	 *	SHA2-512/256
	 *
	 * HMAC DRBG:
	 *	SHA-1
	 *	SHA2-224
	 *	SHA2-256
	 *	SHA2-384
	 *	SHA2-512
	 *	SHA2-512/224
	 *	SHA2-512/256
	 *
	 * CTR DRBG:
	 *	TDES
	 *	AES-128
	 *	AES-192
	 *	AES-256
	 *
	 * required: always
	 */
	cipher_t mode;

	/*
	 * Is derivation function supported?
	 * required: only for CTR DRBG
	 */
	bool df;

	/*
	 * at least the maximum security strength supported by mechanism in
	 * bits, larger values are optional
	 * required: always
	 */
	int entropyinputlen[DEF_ALG_MAX_INT];

	/*
	 * at least half of maximum security strength supported by mechanism
	 * in bits, larger values are optional
	 * required: always
	 */
	int noncelen[DEF_ALG_MAX_INT];

	/*
	 * at least the maximum security strength supported by mechanism in
	 * bits, larger values are optional
	 * Note, if the option is not supported, set all values to zero
	 * required: always
	 */
	int persostringlen[DEF_ALG_MAX_INT];

	/*
	 * at least the maximum security strength supported by mechanism in
	 * bits, larger values are optional
	 * Note, if the option is not supported, set all values to zero
	 * required: always
	 */
	int additionalinputlen[DEF_ALG_MAX_INT];

	/*
	 * One value of the number of returned bits supported by DRBG
	 * required: always
	 */
	unsigned int returnedbitslen;
};

struct def_algo_drbg {
	/*
	 * hashDRBG
	 * hmacDRBG
	 * ctrDRBG
	 * required: always
	 */
	const char *algorithm;

	/*
	 * Prerequisites to DRBG
	 * required for the following ciphers:
	 * Hash DRBG: SHA
	 * HMAC DRBG: HMAC
	 * CTR DRBG: AES, TDES
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * Is prediction resistance enabled?
	 * required: always
	 */
#define DEF_ALG_DRBG_PR_ENABLED			(1<<0)
#define DEF_ALG_DRBG_PR_DISABLED		(1<<1)
	unsigned int pr;

	/*
	 * Is reseed implemented?
	 * required: always
	 */
	bool reseed;

	/*
	 * One or more entries defining the capabilities
	 * required: always
	 */
	struct def_algo_drbg_caps capabilities[7];

	/*
	 * Number of capabilities
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int num_caps;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_DRBG_H */
