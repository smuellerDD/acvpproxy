/*
 * Copyright (C) 2026, Joachim Vandersmissen <joachim.vandersmissen@atsec.com>
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

#ifndef DEFINITION_CIPHER_XECDH_H
#define DEFINITION_CIPHER_XECDH_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XECDH
 */
struct def_algo_xecdh {
	/*
	 * XECDH mode type
	 * required: always
	 */
	enum xecdh_mode {
		DEF_ALG_XECDH_MODE_KEYGEN,
		DEF_ALG_XECDH_MODE_KEYVER,
		DEF_ALG_XECDH_MODE_SSC
	} xecdh_mode;

	/*
	 * Prerequisites to XECDH
	 * required: always
	 * DRBG
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * ACVP_CURVE25519
	 * ACVP_CURVE448
	 *
	 * required: always
	 */
	cipher_t curve;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_XECDH_H */
