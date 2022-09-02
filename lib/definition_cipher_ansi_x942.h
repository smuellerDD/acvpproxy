/*
 * Copyright (C) 2022 - 2022, Joachim Vandersmissen <joachim@atsec.com>
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
 * This header file defines the required data for ANSI X9.42 KDF ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structure is @struct def_algo_ansi_x942.
 */

#ifndef DEFINITION_CIPHER_ANSI_X942_H
#define DEFINITION_CIPHER_ANSI_X942_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_ansi_x942 {
	/*
	 * Prerequisites to ANSI X9.42 KDF
	 * required: always
	 * SHA
	 */
	const struct def_algo_prereqs prereqvals;

	/*
	 * The type of KDF (can be multiple values)
	 * required: always
	 */
#define DEF_ALG_ANSI_X942_KDF_DER (1 << 0)
#define DEF_ALG_ANSI_X942_KDF_CONCATENATION (1 << 1)
	unsigned int kdf_type;

	/*
	 * Length of output key - bits
	 *
	 * This can be a domain definition.
	 *
	 * required: always
	 */
	int key_len[DEF_ALG_MAX_INT];

	/*
	 * Length in bits of other info for "concatentation" kdfType
	 *
	 * This can be a domain definition.
	 *
	 * required: when kdf_type is set to "concatenation"
	 */
	int other_info_len[DEF_ALG_MAX_INT];

	/*
	 * Length in bits of supplemental public and private info for "DER" kdfType
	 *
	 * This can be a domain definition.
	 *
	 * required: when kdf_type is set to "DER"
	 */
	int supp_info_len[DEF_ALG_MAX_INT];

	/*
	 * The length of ZZ in bits
	 *
	 * This can be a domain definition.
	 *
	 * required: always
	 */
	int zz_len[DEF_ALG_MAX_INT];

	/*
	 * The OID labels to use, required for "DER" kdfType
	 * required: when kdf_type is set to "DER"
	 */
#define DEF_ALG_ANSI_X942_OID_TDES (1 << 0)
#define DEF_ALG_ANSI_X942_OID_AES_128_KW (1 << 1)
#define DEF_ALG_ANSI_X942_OID_AES_192_KW (1 << 2)
#define DEF_ALG_ANSI_X942_OID_AES_256_KW (1 << 3)
	unsigned int oid;

	/*
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
	 * required: always
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ANSI_X942_H */
