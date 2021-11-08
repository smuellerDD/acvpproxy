/*
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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
 * be instantiated. The root of the data structures is @struct def_algo_x963 for
 * HMAC and @struct def_algo_cmac for CMAC.
 */

#ifndef DEFINITION_CIPHER_ANSI_X963_H
#define DEFINITION_CIPHER_ANSI_X963_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_ansi_x963 {
	/*
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * Prerequisite:
	 * SHA
	 * required: currently not defined in ACVP spec
	 */
//	const struct def_algo_prereqs prereqvals;

	/*
	 * Shared Info length supported by the KDF in bits between 0 and 1024
	 *
	 * This can be a domain definition.
	 *
	 * required: always
	 */
	int shared_info_len[DEF_ALG_MAX_INT];

	/*
	 * Minimum and Maximum field size in bits
	 *
	 * Any non-empty subset of {224, 233, 256, 283, 384, 409, 521, 571}
	 *
	 * required: always
	 */
	int field_size[2];

	/*
	 * Key length minimum and maximum between 128 and 4096
	 *
	 * This can be a domain definition.
	 *
	 * required: always
	 */
	int key_data_len[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_ANSI_X963_H */
