/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_XOF_H
#define DEFINITION_CIPHER_XOF_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XOF
 */
struct def_algo_xof {
	/*
	 * ACVP_CSHAKE128
	 * ACVP_CSHAKE256
	 * ACVP_KMAC128
	 * ACVP_KMAC256
	 *
	 * required: always
	 */
	cipher_t algorithm;

	/*
	 * Implementation has the ability to act as an XOF or a non-XOF
	 * algorithm.
	 *
	 * required: for ACVP_KMAC*
	 */
#define DEF_ALG_XOF_NOT_PRESENT (1 << 0)
#define DEF_ALG_XOF_PRESENT (1 << 1)
	unsigned int xof;

	/*
	 * An optional feature to the implementation. When true, "hex"
	 * customization strings are supported, otherwise they aren’t. ASCII
	 * strings SHALL be tested regardless of the value within the
	 * hex property.
	 *
	 * required: optional
	 */
	bool hex;

	/*
	 * Minimum and maximum message length (0 - 65536)
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int messagelength[DEF_ALG_MAX_INT];

	/*
	 * Minimum and maximum output length for SHAKE (16 - 65536)
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int outlength[DEF_ALG_MAX_INT];

	/*
	 * Minimum and maximum KMAC key length (128 - 524288)
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: for ACVP_KMAC*
	 */
	int keylength[DEF_ALG_MAX_INT];

	/*
	 * Minimum and maximum MAC length for KMAC (32 - 65536)
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: for ACVP_KMAC*
	 */
	int maclength[DEF_ALG_MAX_INT];
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_XOF_H */
