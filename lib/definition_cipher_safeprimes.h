/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_SAFEPRIMES_H
#define DEFINITION_CIPHER_SAFEPRIMES_H

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_safeprimes {
	/*
	 * Prerequisites to KAS FFC
	 * required: always
	 * DRBG
	 */
	const struct def_algo_prereqs prereqvals;

	/*
	 * The SafePrime mode to be validated
	 *
	 * required: always
	 */
	enum safeprimes_mode {
		DEF_ALG_SAFEPRIMES_KEYGENERATION,
		DEF_ALG_SAFEPRIMES_KEYVERIFICATION,
	} safeprime_mode;

	/*
	 * SafePrime groups to test with. One or more of the following are
	 * allowed. Use OR to combine more than one.
	 *
	 * ACVP_DH_MODP_2048
	 * ACVP_DH_MODP_3072
	 * ACVP_DH_MODP_4096
	 * ACVP_DH_MODP_6144
	 * ACVP_DH_MODP_8192
	 * ACVP_DH_FFDHE_2048
	 * ACVP_DH_FFDHE_3072
	 * ACVP_DH_FFDHE_4096
	 * ACVP_DH_FFDHE_6144
	 * ACVP_DH_FFDHE_8192
	 *
	 * required: always
	 */
	cipher_t safeprime_groups;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_SAFEPRIMES_H */
