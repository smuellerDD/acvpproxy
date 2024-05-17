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
	 * Specify the ML-DSA parameter set as defined in FIPS 204
	 *
	 * required: always
	 */
#define DEF_ALG_ML_DSA_44 (1 << 0)
#define DEF_ALG_ML_DSA_65 (1 << 1)
#define DEF_ALG_ML_DSA_87 (1 << 2)
	unsigned int parameter_set;

	/*
	 * Specify the ML-DSA signature generation approach as defined in
	 * FIPS 204.
	 *
	 * required: for signature generation
	 */
#define DEF_ALG_ML_DSA_SIGGEN_NON_DETERMINISTIC (1 << 0)
#define DEF_ALG_ML_DSA_SIGGEN_DETERMINISTIC (1 << 1)
	unsigned int deterministic;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ML_DSA_H */
