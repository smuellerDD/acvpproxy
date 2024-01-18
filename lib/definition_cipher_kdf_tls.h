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
 * This header file defines the required data for TLS v1.0 / v1.1 / v1.2 KDF
 * ciphers. In order to define a given implementation, the following data
 * structure must be instantiated. The root of the data structures is
 * @struct def_algo_kdf_tls.
 */

#ifndef DEFINITION_CIPHER_KDF_TLS_H
#define DEFINITION_CIPHER_KDF_TLS_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-135 KDF: TLS
 ****************************************************************************/
struct def_algo_kdf_tls {
	/*
	 * Prerequisites to KDF TLS
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
	 * The version of the TLS supported.
	 *
	 * NOTE: For TLS version 1.0 / 1.1 you MUST use DEF_ALG_TYPE_KDF_TLS;
	 *	 for TLS version 1.2 you MUST use DEF_ALG_TYPE_KDF_TLS12
	 *
	 * required: always
	 */
#define DEF_ALG_KDF_TLS_1_0_1_1 (1 << 0)
#define DEF_ALG_KDF_TLS_1_2 (1 << 1)
	unsigned int tls_version;

	/*
	 * SHA functions supported if TLS version 1.2 (DEF_ALG_KDF_TLS_1_2)
	 * is included in the registration.
	 *
	 * Add one or more of the following by ORing
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 *
	 * required: only when DEF_ALG_KDF_TLS_1_2 is selected
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_TLS_H */
