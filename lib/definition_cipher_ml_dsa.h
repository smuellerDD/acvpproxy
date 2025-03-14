/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for ML_DSA (FIPS 204) ciphers. In
 * order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is @struct def_algo_ml_dsa.
 */

#ifndef DEFINITION_CIPHER_ML_DSA_H
#define DEFINITION_CIPHER_ML_DSA_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_ml_dsa_caps {
	/*
	 * Specify the ML-DSA parameter set as defined in FIPS 204
	 *
	 * required: always
	 */
#define DEF_ALG_ML_DSA_44 (1 << 0)
#define DEF_ALG_ML_DSA_65 (1 << 1)
#define DEF_ALG_ML_DSA_87 (1 << 2)
	unsigned int parameter_set;

	/*
	 * The message lengths in bits supported by the IUT.
	 * Minimum allowed is 0, maximum allowed is 65535.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int messagelength[DEF_ALG_MAX_INT];

	/*
	 * The hash algorithms available to the IUT.
	 *
	 * One or more of the following are allowed
	 * SHA2-224
	 * SHA2-256
	 * SHA2-384
	 * SHA2-512
	 * SHA2-512/224
	 * SHA2-512/256
	 * SHA3-224
	 * SHA3-256
	 * SHA3-384
	 * SHA3-512
	 *
	 * required: optional for signature generation / verification (if
	 *	     present, it marks pre-hashed variant of ML-DSA)
	 */
	cipher_t hashalg;

	/*
	 * The context lengths in bits supported by the IUT.
	 * Minimum allowed is 0, maximum allowed is 65535.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: optional
	 */
	int contextlength[DEF_ALG_MAX_INT];
};

struct def_algo_ml_dsa {
	/*
	 * ML-DSA mode type
	 *
	 * required: always
	 */
	enum ml_dsa_mode {
		DEF_ALG_ML_DSA_MODE_KEYGEN,
		DEF_ALG_ML_DSA_MODE_SIGGEN,
		DEF_ALG_ML_DSA_MODE_SIGVER,
	} ml_dsa_mode;

	/*
	 * Capabilities for this algorithm definition. For the keyGen mode,
	 * exactly one capability is required. Other modes permit an arbitrary
	 * number of capabilities.
	 *
	 * required: always
	 */
	union {
		const struct def_algo_ml_dsa_caps *keygen;
		const struct def_algo_ml_dsa_caps *siggen;
		const struct def_algo_ml_dsa_caps *sigver;
	} capabilities;

	/*
	 * Number of capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int capabilities_num;

	/*
	 * Specify the ML-DSA signature generation approach as defined in
	 * FIPS 205.
	 *
	 * required: for signature generation
	 */
#define DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC (1 << 0)
#define DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC (1 << 1)
	unsigned int deterministic;

	/*
	 * Specify the ML-DSA signature interface to be used for testing.
	 *
	 * required: for signature generation and verification
	 */
#define DEF_ALG_ML_DSA_INTERFACE_EXTERNAL (1 << 0)
#define DEF_ALG_ML_DSA_INTERFACE_INTERNAL (1 << 1)
	unsigned int interface;

	/*
	 * Specify the ML-DSA mu generation approach.
	 *
	 * required: for signature generation and verification if the internal
	 * interface is supported
	 */
#define DEF_ALG_ML_DSA_INTERNAL_MU (1 << 0)
#define DEF_ALG_ML_DSA_EXTERNAL_MU (1 << 1)
	unsigned int external_mu;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ML_DSA_H */
