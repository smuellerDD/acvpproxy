/* API for ACVP Proxy definition implementations
 *
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

#ifndef DEFINITION_H
#define DEFINITION_H

#include "aux_helper.h"
#include "constructor.h"

#include "definition_cipher_ansi_x942.h"
#include "definition_cipher_ansi_x963.h"
#include "definition_cipher_drbg.h"
#include "definition_cipher_hash.h"
#include "definition_cipher_mac.h"
#include "definition_cipher_sym.h"
#include "definition_cipher_rsa.h"
#include "definition_cipher_ecdsa.h"
#include "definition_cipher_eddsa.h"
#include "definition_cipher_dsa.h"
#include "definition_cipher_kas_ecc.h"
#include "definition_cipher_kas_ecc_r3.h"
#include "definition_cipher_kas_ffc.h"
#include "definition_cipher_kas_ffc_r3.h"
#include "definition_cipher_kdf_srtp.h"
#include "definition_cipher_kdf_ssh.h"
#include "definition_cipher_kdf_tpm.h"
#include "definition_cipher_kdf_ikev1.h"
#include "definition_cipher_kdf_ikev2.h"
#include "definition_cipher_kdf_tls.h"
#include "definition_cipher_kdf_tls13.h"
#include "definition_cipher_kdf_108.h"
#include "definition_cipher_hkdf.h"
#include "definition_cipher_pbkdf.h"
#include "definition_cipher_kas_ifc.h"
#include "definition_cipher_safeprimes.h"
#include "definition_cipher_conditioning_components.h"
#include "definition_cipher_kdf_onestep.h"
#include "definition_cipher_kdf_twostep.h"
#include "definition_cipher_xof.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This data structure defines a particular cipher algorithm
 *	  definition.
 *
 * @var type Specify the cipher type.
 * @var algo Fill in the data structure corresponding to the @param type
 *	       selection.
 */
struct def_algo {
	enum def_algo_type {
		/** symmetric ciphers, incl. AEAD */
		DEF_ALG_TYPE_SYM,
		/** SHA hashes */
		DEF_ALG_TYPE_SHA,
		/** SHAKE cipher */
		DEF_ALG_TYPE_SHAKE,
		/** HMAC ciphers */
		DEF_ALG_TYPE_HMAC,
		/** CMAC ciphers */
		DEF_ALG_TYPE_CMAC,
		/** SP800-90A DRBG cipher */
		DEF_ALG_TYPE_DRBG,
		/** FIPS 186-4 RSA cipher */
		DEF_ALG_TYPE_RSA,
		/** FIPS 186-4 ECDSA cipher */
		DEF_ALG_TYPE_ECDSA,
		/** Bernstein EDDSA cipher */
		DEF_ALG_TYPE_EDDSA,
		/** FIPS 186-4 DSA cipher */
		DEF_ALG_TYPE_DSA,
		/** KAS_ECC (ECDH, ECMQV) cipher */
		DEF_ALG_TYPE_KAS_ECC,
		/** KAS_ECC (Finite Field DH, Finite Field MQV) cipher */
		DEF_ALG_TYPE_KAS_FFC,
		/** SP800-135 KDF: SSH */
		DEF_ALG_TYPE_KDF_SSH,
		/** SP800-135 KDF: IKE v1 */
		DEF_ALG_TYPE_KDF_IKEV1,
		/** SP800-135 KDF: IKE v2 */
		DEF_ALG_TYPE_KDF_IKEV2,
		/** SP800-135 KDF: TLS */
		DEF_ALG_TYPE_KDF_TLS,
		/** SP800-135 / RFC7627 KDF: TLS */
		DEF_ALG_TYPE_KDF_TLS12,
		/** RFC8446 KDF: TLS 1.3 */
		DEF_ALG_TYPE_KDF_TLS13,
		/** SP800-108 KDF */
		DEF_ALG_TYPE_KDF_108,
		/** SP800-132 PBKDF */
		DEF_ALG_TYPE_PBKDF,
		/** SP800-56A rev3 FFC */
		DEF_ALG_TYPE_KAS_FFC_R3,
		/** SP800-56A rev3 KAS ECC */
		DEF_ALG_TYPE_KAS_ECC_R3,
		/** SP800-56A rev 3 Safe Primes */
		DEF_ALG_TYPE_SAFEPRIMES,
		/** SP800-56B rev2 KAS IFC (RSA) */
		DEF_ALG_TYPE_KAS_IFC,
		/** SP800-56C rev 1 HKDF (RFC 5869) */
		DEF_ALG_TYPE_HKDF,
		/** SP800-90B conditioning components */
		DEF_ALG_TYPE_COND_COMP,
		/** SP800-56C rev 1 onestep KDF */
		DEF_ALG_TYPE_KDF_ONESTEP,
		/** SP800-56C rev 1 twostep KDF */
		DEF_ALG_TYPE_KDF_TWOSTEP,
		/** SP800-135 TPM KDF */
		DEF_ALG_TYPE_KDF_TPM,
		/** ANSI X9.63 */
		DEF_ALG_TYPE_ANSI_X963,
		/** SP800-135 KDF: SRTP */
		DEF_ALG_TYPE_KDF_SRTP,
		/** SP800-185: XOF */
		DEF_ALG_TYPE_XOF,
		/** ANSI X9.42 */
		DEF_ALG_TYPE_ANSI_X942,
	} type;
	union {
		/** DEF_ALG_TYPE_SYM */
		struct def_algo_sym sym;
		/** DEF_ALG_TYPE_SHA */
		struct def_algo_sha sha;
		/** DEF_ALG_TYPE_SHAKE */
		struct def_algo_shake shake;
		/** DEF_ALG_TYPE_HMAC */
		struct def_algo_hmac hmac;
		/** DEF_ALG_TYPE_CMAC */
		struct def_algo_cmac cmac;
		/** DEF_ALG_TYPE_DRBG */
		struct def_algo_drbg drbg;
		/** DEF_ALG_TYPE_RSA */
		struct def_algo_rsa rsa;
		/** DEF_ALG_TYPE_ECDSA */
		struct def_algo_ecdsa ecdsa;
		/** DEF_ALG_TYPE_EDDSA */
		struct def_algo_eddsa eddsa;
		/** DEF_ALG_TYPE_DSA */
		struct def_algo_dsa dsa;
		/** DEF_ALG_TYPE_KAS_ECC */
		struct def_algo_kas_ecc kas_ecc;
		/** DEF_ALG_TYPE_KAS_FFC */
		struct def_algo_kas_ffc kas_ffc;
		/** DEF_ALG_TYPE_KDF_SSH */
		struct def_algo_kdf_ssh kdf_ssh;
		/** DEF_ALG_TYPE_KDF_IKEV1 */
		struct def_algo_kdf_ikev1 kdf_ikev1;
		/** DEF_ALG_TYPE_KDF_IKEV2 */
		struct def_algo_kdf_ikev2 kdf_ikev2;
		/** DEF_ALG_TYPE_KDF_TLS / DEF_ALG_TYPE_KDF_TLS12 */
		struct def_algo_kdf_tls kdf_tls;
		/** DEF_ALG_TYPE_KDF_TLS 1.3 */
		struct def_algo_kdf_tls13 kdf_tls13;
		/** DEF_ALG_TYPE_KDF_108 */
		struct def_algo_kdf_108 kdf_108;
		/** DEF_ALG_TYPE_PBKDF */
		struct def_algo_pbkdf pbkdf;
		/** DEF_ALG_TYPE_KAS_FFC_R3 */
		struct def_algo_kas_ffc_r3 kas_ffc_r3;
		/** DEF_ALG_TYPE_KAS_ECC_R3 */
		struct def_algo_kas_ecc_r3 kas_ecc_r3;
		/** DEF_ALG_TYPE_SAFEPRIMES */
		struct def_algo_safeprimes safeprimes;
		/** DEF_ALG_TYPE_KAS_IFC */
		struct def_algo_kas_ifc kas_ifc;
		/** DEF_ALG_TYPE_HKDF */
		struct def_algo_hkdf hkdf;
		/** DEF_ALG_TYPE_COND_COMP */
		struct def_algo_cond_comp cond_comp;
		/** DEF_ALG_TYPE_KDF_ONESTEP */
		struct def_algo_kdf_onestep kdf_onestep;
		/** DEF_ALG_TYPE_KDF_TWOSTEP */
		struct def_algo_kdf_twostep kdf_twostep;
		/** DEF_ALG_TYPE_KDF_TPM */
		struct def_algo_kdf_tpm kdf_tpm;
		/** DEF_ALG_TYPE_ANSI_X963 */
		struct def_algo_ansi_x963 ansi_x963;
		/** DEF_ALG_TYPE_KDF_SRTP */
		struct def_algo_kdf_srtp kdf_srtp;
		/** DEF_ALG_TYPE_XOF */
		struct def_algo_xof xof;
		/** DEF_ALG_TYPE_ANSI_X942 */
		struct def_algo_ansi_x942 ansi_x942;
	} algo;
};

struct def_algo_map {
	const struct def_algo *algos;
	unsigned int num_algos;
	const char *algo_name;
	const char *processor;
	const char *impl_name;
	const char *impl_description;
	struct def_algo_map *next;
};

/**
 * @brief Data structure to for registering out-of-tree module implementation
 *	  definitions. This structure should only be used with the
 *	  ACVP_EXTENSION macro.
 */
struct acvp_extension {
	struct def_algo_map *curr_map;
	unsigned int nrmaps;
};

#define SET_IMPLEMENTATION(impl) .algos = impl, .num_algos = ARRAY_SIZE(impl)

#define IMPLEMENTATION(imp, alg_name, proc, imple_name, imple_description)\
	{								\
		SET_IMPLEMENTATION(imp),				\
		.algo_name = alg_name,					\
		.processor = proc,					\
		.impl_name = imple_name,				\
		.impl_description = imple_description			\
	}

#if defined(ACVPPROXY_EXTENSION)
#define ACVP_EXTENSION(map)                                                    \
	__attribute__((visibility(                                             \
		"default"))) struct acvp_extension acvp_extension = {          \
		map, ARRAY_SIZE(map)                                           \
	};
#else
#define ACVP_EXTENSION(map)
#endif

/**
 * @brief Register uninstantiated algorithm definitions (i.e. definitions
 *	  without meta data of module information, operational environment,
 *	  and vendor information).
 *
 * @param curr_map Pointer to the uninstantiated algorithm definition.
 * @param nrmaps Number of map definitions pointed to by curr_map
 */
void acvp_register_algo_map(struct def_algo_map *curr_map,
			    const unsigned int nrmaps);

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_H */
