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
 * This header file defines the required data for SHA and SHAKE ciphers.
 * In order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is @struct def_algo_sha for
 * SHA and @struct def_algo_shake for SHAKE.
 */

#ifndef DEFINITION_CIPHER_HASH_H
#define DEFINITION_CIPHER_HASH_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * SHA-1, SHA-2, and SHA-3 hashes
 */
struct def_algo_sha {
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
	cipher_t algorithm;

	/*
	 * The message lengths in bits supported by the IUT.
	 * Minimum allowed is 0, maximum allowed is 65535.
	 *
	 * required: optional
	 */
	int messagelength[DEF_ALG_MAX_INT];

	/*
	 * Implementation does not accept bit-oriented messages
	 * required: always
	 */
	bool inbit;

	/*
	 * Implementation does accept null (zero-length) messages
	 * required: always
	 */
	bool inempty;
};

/*
 * SHAKE
 */
struct def_algo_shake {
	/*
	 * ACVP_SHAKE128
	 * ACVP_SHAKE256
	 * required: always
	 */
	cipher_t algorithm;

	/*
	 * Implementation does not accept bit-oriented messages
	 * required: always
	 */
	bool inbit;

	/*
	 * Implementation does accept null (zero-length) messages
	 * required: always
	 */
	bool inempty;

	/*
	 * Output length for SHAKE (16 - 65536)
	 * required: always
	 */
	int outlength[DEF_ALG_MAX_INT];

	/*
	 * SHAKE is able to produce bit-oriented messages?
	 * required: always
	 */
	bool outbit;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_HASH_H */
