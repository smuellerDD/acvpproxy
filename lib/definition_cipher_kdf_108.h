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
 * This header file defines the required data for SP800-108 KDF ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structures is @struct def_algo_kdf_108.
 */

#ifndef DEFINITION_CIPHER_KDF_108_H
#define DEFINITION_CIPHER_KDF_108_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-108 KDF
 ****************************************************************************/
struct def_algo_kdf_108 {
	/*
	 * Prerequisites to KDF SP 800-108
	 * required: always
	 * KAS
	 * DRBG
	 * HMAC
	 * CMAC
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * The KDF mode for testing.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
	enum kdf_108_type {
		DEF_ALG_KDF_108_COUNTER,
		DEF_ALG_KDF_108_FEEDBACK,
		DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION,
	} kdf_108_type;

	/*
	 * The MAC used in the KDF.
	 *
	 * Add one or more of the following by ORing
	 * ACVP_CMAC_AES128
	 * ACVP_CMAC_AES192
	 * ACVP_CMAC_AES256
	 * ACVP_CMAC_TDES
	 * ACVP_HMACSHA1
	 * ACVP_HMACSHA2_224
	 * ACVP_HMACSHA2_256
	 * ACVP_HMACSHA2_384
	 * ACVP_HMACSHA2_512
	 * ACVP_KMAC128
	 * ACVP_KMAC256
	 *
	 * required: always
	 */
	cipher_t macalg;

	/*
	 * The supported derived keying material lengths in bits.
	 *
	 * Minimum must be greater or equal to 1. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
	int supported_lengths[DEF_ALG_MAX_INT];

	/*
	 * Describes where the counter appears in the fixed data.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
#define DEF_ALG_KDF_108_COUNTER_ORDER_NONE (1 << 0)
#define DEF_ALG_KDF_108_COUNTER_ORDER_AFTER_FIXED_DATA (1 << 1)
#define DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA (1 << 2)
#define DEF_ALG_KDF_108_COUNTER_ORDER_MIDDLE_FIXED_DATA (1 << 3)
#define DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_ITERATOR (1 << 4)
	unsigned int fixed_data_order;

	/*
	 * Valid counter lengths that appears in the fixed data.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
#define DEF_ALG_KDF_108_COUNTER_LENGTH_0 (1 << 0)
#define DEF_ALG_KDF_108_COUNTER_LENGTH_8 (1 << 1)
#define DEF_ALG_KDF_108_COUNTER_LENGTH_16 (1 << 2)
#define DEF_ALG_KDF_108_COUNTER_LENGTH_24 (1 << 3)
#define DEF_ALG_KDF_108_COUNTER_LENGTH_32 (1 << 4)
	unsigned int counter_lengths;

	/*
	 * Whether the IUT supports an empty IV.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
	bool supports_empty_iv;

	/*
	 * Whether the IUT requires an empty IV.
	 *
	 * required: always for HMAC or CMAC based KDFs
	 */
	bool requires_empty_iv;

	/*
	 * Optional value used to control the length of the keyIn produced by
	 * the ACVP server for the capability.
	 *
	 * required: optional for HMAC or CMAC based KDFs
	 */
	int custom_key_in_length;

	/*
	 * The length of the key derivation key in bits.
	 *
	 * Minimum must be greater or equal to 112. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always for KMAC based KDFs
	 */
	int key_derivation_key_length[DEF_ALG_MAX_INT];

	/*
	 * The length of the context field in bits.
	 *
	 * Minimum must be greater or equal to 8. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always for KMAC based KDFs
	 */
	int context_length[DEF_ALG_MAX_INT];

	/*
	 * The lengths of the label field in bits. This field can be excluded
	 * if no label is used.
	 *
	 * Minimum must be greater or equal to 8. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: optional for KMAC based KDFs
	 */
	int label_length[DEF_ALG_MAX_INT];

	/*
	 * The lengths of the derived keys in bits.
	 *
	 * Minimum must be greater or equal to 112. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always for KMAC based KDFs
	 */
	int derived_key_length[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_108_H */
