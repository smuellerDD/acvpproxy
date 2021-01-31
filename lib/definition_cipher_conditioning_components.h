/*
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_CONDITIONING_COMPONENT_H
#define DEFINITION_CIPHER_CONDITIONING_COMPONENT_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_cond_comp {
	/*
	 * Conditioning Component mode:
	 *
	 * ACVP_COND_COMP_HASH_DF
	 * ACVP_COND_COMP_BLOCK_DF
	 * ACVP_COND_COMP_CBC_MAC
	 *
	 * required: always
	 */
	cipher_t mode;

	/*
	 * Conditioning Component cipher algorithm:
	 *
	 * ACVP_SHA1
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 *
	 * required: only for ACVP_COND_COMP_HASH_DF
	 */
	cipher_t hashalg;

	/*
	 * Key length in bits
	 * required: for ACVP_COND_COMP_BLOCK_DF and ACVP_COND_COMP_CBC_MAC
	 */
#define DEF_ALG_SYM_KEYLEN_128 (1 << 0)
#define DEF_ALG_SYM_KEYLEN_192 (1 << 2)
#define DEF_ALG_SYM_KEYLEN_256 (1 << 3)
	unsigned int keylen;

	/*
	 * Length of the data to be generated. It allows a range between
	 * 1 and 65536.
	 *
	 * required: required
	 */
	int derived_len[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_CONDITIONING_COMPONENT_H */
