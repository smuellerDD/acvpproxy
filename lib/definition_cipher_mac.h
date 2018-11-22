/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for HMAC and CMAC ciphers. In
 * order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is @struct def_algo_hmac for
 * HMAC and @struct def_algo_cmac for CMAC.
 */

#ifndef DEFINITION_CIPHER_MAC_H
#define DEFINITION_CIPHER_MAC_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct def_algo_hmac {
	/*
	 * HMAC-SHA-1
	 * HMAC-SHA2-224
	 * HMAC-SHA2-256
	 * HMAC-SHA2-384
	 * HMAC-SHA2-512
	 * HMAC-SHA2-512/224
	 * HMAC-SHA2-512/256
	 * HMAC-SHA3-224
	 * HMAC-SHA3-256
	 * HMAC-SHA3-384
	 * HMAC-SHA3-512
	 * required: always
	 */
	cipher_t algorithm;

	/*
	 * Prerequisite:
	 * SHA
	 * required: always
	 */
	const struct def_algo_prereqs prereqvals;

	/*
	 * Key length supported by the HMAC in bits between 8 and 524288
	 * required: always
	 */
	int keylen[DEF_ALG_MAX_INT];
};

struct def_algo_cmac {
	/*
	 * CMAC-AES
	 * CMAC-TDES
	 * required: always
	 */
	cipher_t algorithm;

	/*
	 * Prerequisite:
	 * AES, TDES
	 * required: always
	 */
	const struct def_algo_prereqs prereqvals;

	/*
	 * The MAC direction(s) to be tested
	 * required: always
	 */
#define DEF_ALG_CMAC_GENERATION		(1<<0)
#define DEF_ALG_CMAC_VERIFICATION	(1<<1)
	unsigned int direction;

	/*
	 * Key length in bits
	 * use DEF_ALG_SYM_KEYLEN_* flags
	 * required: always
	 */
	unsigned int keylen;

	/*
	 * Message length supported by the CMAC in bits between 8 and 65536
	 * required: always
	 */
	int msglen[DEF_ALG_MAX_INT];

};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_MAC_H */
