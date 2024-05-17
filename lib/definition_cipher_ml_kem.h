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
 * This header file defines the required data for ML_KEM (FIPS 203) ciphers. In
 * order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is @struct def_algo_ml_kem.
 */

#ifndef DEFINITION_CIPHER_ML_KEM_H
#define DEFINITION_CIPHER_ML_KEM_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_ml_kem {
	/*
	 * ML-KEM mode type
	 *
	 * required: always
	 */
	enum ml_kem_mode {
		DEF_ALG_ML_KEM_MODE_KEYGEN,
		DEF_ALG_ML_KEM_MODE_ENCAPSULATION,
		DEF_ALG_ML_KEM_MODE_DECAPSULATION,
	} ml_kem_mode;
	/*
	 * Specify the ML-KEM parameter set as defined in FIPS 203
	 *
	 * required: always
	 */
#define DEF_ALG_ML_KEM_512 (1 << 0)
#define DEF_ALG_ML_KEM_768 (1 << 1)
#define DEF_ALG_ML_KEM_1024 (1 << 2)
	unsigned int parameter_set;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ML_KEM_H */
