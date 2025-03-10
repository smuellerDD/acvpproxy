/*
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_KDF_ONESTEP_H
#define DEFINITION_CIPHER_KDF_ONESTEP_H

#include "definition_common.h"
#include "definition_cipher_kas_kdf_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-56C rev 1 and 2 Onestep KDF
 ****************************************************************************/
struct def_algo_kdf_onestep {
	/*
	 * Prerequisites to Onestep KDF
	 * required: always
	 * DRBG
	 * HMAC
	 * KMAC
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
	 * KDF specification that is to be applied
	 *
	 * required: optional - if not set SP800-56Cr1 is assumed
	 */
	enum kdf_spec kdf_spec;

	/*
	 * Definitions of the one-step KDF
	 *
	 * required: always
	 */
	struct def_algo_kas_kdf_onestepkdf onestep;

	/*
	 * The length of the key to derive. This value should be large enough
	 * to accommodate the key length used for the MAC algorithms in use for
	 * the key confirmation. Maximum value (for testing purposes) is 2048.
	 *
	 * Minimum without key confirmation is 128.
	 * Minimum with key confirmation is 136.
	 * Maximum is 2048
	 *
	 * required: always for OneStep, not required for OneStepNoCounter
	 */
	unsigned int length;

	/*
	 * The domain of values representing the min/max lengths of Z the
	 * implementation can support.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int zlen[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_ONESTEP_H */
