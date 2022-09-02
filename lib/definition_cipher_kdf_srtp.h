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
 * This header file defines the required data for SRTP KDF ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structure is @struct def_algo_kdf_srtp.
 */

#ifndef DEFINITION_CIPHER_KDF_SRTP_H
#define DEFINITION_CIPHER_KDF_SRTP_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_kdf_srtp {
	/*
	 * Prerequisites to KDF SRTP
	 * required: always
	 * AES
	 */
	const struct def_algo_prereqs prereqvals;

	/*
	 * AES key length in bits
	 * required: always
	 */
#define DEF_ALG_KDF_SRTP_KEYLEN_128 (1 << 0)
#define DEF_ALG_KDF_SRTP_KEYLEN_192 (1 << 1)
#define DEF_ALG_KDF_SRTP_KEYLEN_256 (1 << 2)
	unsigned int aes_key_length;

	/*
	 * Whether or not the IUT supports an empty KDR
	 * required: always
	 */
	bool supports_zero_kdr;

	/*
	 * Key Derivation Rate as an exponent of 2
	 * required: only if supports_zero_kdr is set to false
	 */
	int kdr_exponent[25];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_SRTP_H */
