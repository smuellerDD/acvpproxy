/*
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for IKE v1 KDF ciphers.
 * In order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is
 * @struct def_algo_kdf_ikev1.
 */

#ifndef DEFINITION_CIPHER_KDF_IKEV1_H
#define DEFINITION_CIPHER_KDF_IKEV1_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-135 KDF: IKE v1
 ****************************************************************************/
struct def_algo_kdf_ikev1 {
	/*
	 * Prerequisites to KDF IKE v1
	 * required: always
	 * SHA
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
	 * The mode of the authentication used by the IUT
	 *
	 * required
	 */
	enum authentication_method {
		DEF_ALG_KDF_IKEV1_DSA,
		DEF_ALG_KDF_IKEV1_PSK,
		DEF_ALG_KDF_IKEV1_PKE
	} authentication_method;

	/*
	 * The supported in initiator nonce lengths used by the IUT.
	 *
	 * Minimum must be greater or equal to 64. Maximum must be less than
	 * or equal to 2048.
	 *
	 * required: always
	 */
	int initiator_nonce_length[DEF_ALG_MAX_INT];

	/*
	 * The lengths of data the IUT supports.
	 *
	 * Minimum must be greater or equal to 64. Maximum must be less than
	 * or equal to 2048.
	 *
	 * required: always
	 */
	int responder_nonce_length[DEF_ALG_MAX_INT];

	/*
	 * The lengths of Diffie Hellman shared secrets the IUT supports.
	 *
	 * Minimum must be greater or equal to 224. Maximum must be less than
	 * or equal to 8192.
	 *
	 * required: always
	 */
	int diffie_hellman_shared_secret_length[DEF_ALG_MAX_INT];

	/*
	 * The lengths of pre-shared key the IUT supports.
	 *
	 * Minimum must be greater than or equal to 8. Maximum must be less
	 * than or equal to 8192.
	 *
	 * required: only when authentication method is DEF_ALG_KDF_IKEV1_PSK.
	 */
	int pre_shared_key_length[DEF_ALG_MAX_INT];

	/*
	 * SHA functions supported
	 *
	 * Add one or more of the following by ORing
	 * ACVP_SHA1
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 *
	 * required: always
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_IKEV1_H */
