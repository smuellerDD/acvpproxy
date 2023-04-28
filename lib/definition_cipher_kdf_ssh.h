/*
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for SSH v2 KDF ciphers.
 * In order to define a given implementation, the following data structures must
 * be instantiated. The root of the data structures is
 * @struct def_algo_kdf_ssh.
 */

#ifndef DEFINITION_CIPHER_KDF_SSH_H
#define DEFINITION_CIPHER_KDF_SSH_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * SP800-135 KDF: SSH
 ****************************************************************************/
struct def_algo_kdf_ssh {
	/*
	 * Prerequisites to KDF SSH
	 * required: always
	 * SHA
	 * AES
	 * TDES
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * Block ciphers supported
	 * Add one or more of the following by ORing
	 * ACVP_AES128
	 * ACVP_AES192
	 * ACVP_AES256
	 *
	 * required: always
	 */
	cipher_t cipher;

	/*
	 * SHA functions supported
	 *
	 * Add one or more of the following by ORing
	 * ACVP_SHA1
	 * ACVP_SHA224
	 * ACVP_SHA256
	 * ACVP_SHA384
	 * ACVP_SHA512
	 *
	 * required: always
	 */
	cipher_t hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_KDF_SSH_H */
