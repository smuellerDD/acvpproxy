/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for TLS v1.3 KDF
 * ciphers. In order to define a given implementation, the following data
 * structure must be instantiated. The root of the data structures is
 * @struct def_algo_kdf_tls13.
 */

#ifndef DEFINITION_CIPHER_KDF_TLS13_H
#define DEFINITION_CIPHER_KDF_TLS13_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * RFC 8446 KDF: TLS 1.3
 ****************************************************************************/
struct def_algo_kdf_tls13 {
	/*
	 * Prerequisites to KDF TLS13
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
	 * The supported key exchange modes for the KDF.
	 *
	 * required: required
	 */
#define DEF_ALG_KDF_TLS13_MODE_DHE (1 << 0)
#define DEF_ALG_KDF_TLS13_MODE_PSK (1 << 1)
#define DEF_ALG_KDF_TLS13_MODE_PSK_DHE (1 << 2)
	unsigned int running_mode;

	/*
	 * SHA functions supported if TLS13 version 1.2 (DEF_ALG_KDF_TLS13_1_2)
	 * is included in the registration.
	 *
	 * Add one or more of the hashes by ORing
	 *
	 * required: always
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_TLS13_H */
