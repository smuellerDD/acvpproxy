/*
 * Copyright (C) 2020 - 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_HKDF_H
#define DEFINITION_CIPHER_HKDF_H

/**
 * This header file defines the required data for SP800-108 KDF ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structures is @struct def_algo_hkdf.
 */

#include "definition_common.h"

#include "definition_cipher_kas_kdf_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-56C rev 1 HKDF (based on RFC 5869)
 ****************************************************************************/
struct def_algo_hkdf_cipher {
	/*
	 * The MAC used in the KDF.
	 *
	 * Add one or more of the following by ORing
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 * ACVP_SHA512224
	 * ACVP_SHA256256
	 * ACVP_SHA3_224
	 * ACVP_SHA3_256
	 * ACVP_SHA3_384
	 * ACVP_SHA3_512
	 *
	 * required: always
	 */
	cipher_t macalg;

	/*
	 * The lengths of value Z (also known as IKM in RFC 5869) the IUT
	 * supports.
	 *
	 * Minimum must be greater or equal to 1. Maximum must be less than
	 * or equal to 4096.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int z[DEF_ALG_MAX_INT];

	/*
	 * The largest DKM the implementation can produce (up to a max of 2048).
	 * This value is also known as OKM in RFC 5869.
	 *
	 * required: always
	 */
	unsigned int l;
};

struct def_algo_hkdf {
	/*
	 * Prerequisites to HKDF SP 800-56C
	 * required: always
	 * HMAC
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * How the salt is determined
	 *
	 * required: always
	 */
#define DEF_ALG_KAS_HKDF_MAC_SALT_UNDEFINED (0)
	/* All bytes are zero bytes */
#define DEF_ALG_KAS_HKDF_MAC_SALT_DEFAULT (1 << 0)
	/* Random salt */
#define DEF_ALG_KAS_HKDF_MAC_SALT_RANDOM (1 << 1)
	unsigned int mac_salt_method;

	/*
	 * Length of the salt value
	 *
	 * required: optional
	 */
	int saltlen;

	/*
	 * The pattern and encoding used for fixedInfo construction.
	 *
	 * If a DEF_ALG_KAS_KDF_FI_PATTERN_LITERAL is specified, the literal
	 * must be provided with *literal which is a hex value.
	 *
	 * required: always
	 */
	enum kas_kdf_fixedinfo_pattern
		fixed_info_pattern_type[DEF_ALG_KAS_KDF_MAX_FIXED_INFO_PATTERN];
	const char *literal;
	enum kas_kdf_fixedinfo_encoding fixed_info_encoding;

	/*
	 * Cipher details of the HKDF operation
	 */
	struct def_algo_hkdf_cipher cipher_spec;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_HKDF_H */
