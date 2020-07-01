/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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
 * This header file defines the required data for RSA implementations. In order
 * to define a given RSA implementation, the following data structures must be
 * instantiated. The root of the data structures is @struct def_algo_rsa.
 * Please start from this data structure and fill in the required field for the
 * requested type of RSA implementation.
 */

#ifndef DEFINITION_CIPHER_RSA_H
#define DEFINITION_CIPHER_RSA_H

#include "definition_common.h"
#include "definition_cipher_rsa_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum rsa_randpq {
	DEF_ALG_RSA_PQ_B32_PRIMES,
	DEF_ALG_RSA_PQ_B33_PRIMES,
	DEF_ALG_RSA_PQ_B34_PRIMES,
	DEF_ALG_RSA_PQ_B35_PRIMES,
	DEF_ALG_RSA_PQ_B36_PRIMES,
};

enum sigtype {
	DEF_ALG_RSA_SIGTYPE_ANSIX931,
	DEF_ALG_RSA_SIGTYPE_PKCS1V15,
	DEF_ALG_RSA_SIGTYPE_PSS,
};

enum pubexpmode {
	DEF_ALG_RSA_PUBEXTMODE_FIXED,
	DEF_ALG_RSA_PUBEXTMODE_RANDOM,
};

enum saltlen {
	DEF_ALG_RSA_PSS_SALT_IGNORE,
	DEF_ALG_RSA_PSS_SALT_ZERO,
	DEF_ALG_RSA_PSS_SALT_HASHLEN,
	DEF_ALG_RSA_PSS_SALT_VALUE,
};

enum keyformat {
	DEF_ALG_RSA_KEYFORMAT_STANDARD,
	DEF_ALG_RSA_KEYFORMAT_CRT,
};

/****************************************************************************
 * RSA key generation specific data
 ****************************************************************************/

struct def_algo_rsa_keygen_caps {
	/*
	 * Supported RSA modulo for the randPQ mode - see [FIPS186-4], Appendix
	 * B.3
	 *
	 * required: always
	 */
	enum rsa_modulo rsa_modulo;

	/*
	 * Supported hash algorithms for the randPQ mode - see [FIPS186-4],
	 * Appendix B.3
	 *
	 * Allowed values:
	 * 	"SHA-1"
	 *	"SHA2-224"
	 *	"SHA2-256"
	 *	"SHA2-384"
	 *	"SHA2-512"
	 *	"SHA2-512/224"
	 *	"SHA2-512/256"
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * Primality test rounds of Miller-Rabin from Table C.2 or Table C.3
	 * in [FIPS186-4], Appendix C.3.
	 *
	 * required: always
	 */
#define DEF_ALG_RSA_PRIMETEST_C2	(1<<0)
#define DEF_ALG_RSA_PRIMETEST_C3	(1<<1)
	unsigned int rsa_primetest;
};

struct def_algo_rsa_keygen_gen {
	/*
	 * This flag indicates that the server is responsible for generating
	 * inputs for generating inputs for Key Generation tests. This flag is
	 * not relevant to KeyGen mode "B.3.3" Random Probable Primes.
	 * required: always
	 */
	bool infogeneratedbyserver;

	/*
	 * Supports fixed or random public key exponent e
	 * required: always
	 */
	enum pubexpmode pubexpmode;

	/*
	 * The value of the public key exponent e in hex
	 *
	 * required: only if DEF_ALG_RSA_PUBEXTMODE_FIXED is selected in
	 * pubexpmode.
	 */
	const char *fixedpubexp;

	/*
	 * The preferred private key format. The DEF_ALG_RSA_KEYFORMAT_STANDARD
	 * format has "p", "q", and "d" as the component of the private key.
	 * The DEF_ALG_RSA_KEYFORMAT_CRT (Chinese Remainder Theorem) format has
	 * "p", "q", "dmp1" (d modulo p-1), "dmq1" (d modulo q-1), and "iqmp"
	 * (inverse q modulo p)) as the components
	 *
	 * required: always
	 */
	enum keyformat keyformat;
};

struct def_algo_rsa_keygen {
	/*
	 * Key Generation mode to be validated. Random P and Q primes
	 * generated as (see [FIPS186-4]):
	 * * provable primes (Appendix B.3.2)
	 * * probable primes (Appendix B.3.3)
	 * * provable primes with conditions (Appendix B.3.4)
	 * * provable/probable primes with conditions (Appendix B.3.5)
	 * * probable primes with conditions (Appendix B.3.6)
	 *
	 * required: always
	 */
	enum rsa_randpq rsa_randpq;

	/*
	 * Capabilities for all supported moduli, primality test and hash
	 * algorithms for a single key generation mode
	 *
	 * required: always
	 */
	const struct def_algo_rsa_keygen_caps *capabilities;

	/*
	 * Number of capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int capabilities_num;
};

/****************************************************************************
 * RSA signature generation specific data
 ****************************************************************************/
struct def_algo_rsa_siggen_caps {
	/*
	 * Supported RSA modulo for the randPQ mode - see [FIPS186-4], Appendix
	 * B.3
	 *
	 * required: always
	 */
	enum rsa_modulo rsa_modulo;

	/*
	 * Supported hash algorithms for the randPQ mode - see [FIPS186-4],
	 * Appendix B.3
	 *
	 * Allowed values:
	 *	"SHA2-224"
	 *	"SHA2-256"
	 *	"SHA2-384"
	 *	"SHA2-512"
	 *	"SHA2-512/224"
	 *	"SHA2-512/256"
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * Salt specification for RSA PSS
	 * required: only for PSS
	 */
	enum saltlen saltlen;

	/*
	 * Length of the PSS salt in bytes.
	 *
	 * This field is only evaluated if saltlen is set to
	 * DEF_ALG_RSA_PSS_SALT_VALUE.
	 * required: optional, only for PSS
	 */
	int saltlen_bytes;
};

struct def_algo_rsa_siggen {
	/*
	 * RSA signature types - see [FIPS140-2] section 5
	 *
	 * required: always
	 */
	enum sigtype sigtype;

	/*
	 * Capabilities for this sigType - see [FIPS186-4] section 5
	 *
	 * required: always
	 */
	const struct def_algo_rsa_siggen_caps *capabilities;

	/*
	 * Number of capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int capabilities_num;
};

/****************************************************************************
 * RSA signature verification specific data
 ****************************************************************************/
struct def_algo_rsa_sigver_caps {
	/*
	 * Supported RSA modulo for the randPQ mode - see [FIPS186-4], Appendix
	 * B.3
	 *
	 * required: always
	 */
	enum rsa_modulo rsa_modulo;

	/*
	 * Supported hash algorithms for the randPQ mode - see [FIPS186-4],
	 * Appendix B.3
	 *
	 * Allowed values:
	 *	"SHA2-224"
	 *	"SHA2-256"
	 *	"SHA2-384"
	 *	"SHA2-512"
	 *	"SHA2-512/224"
	 *	"SHA2-512/256"
	 *
	 * required: always
	 */
	cipher_t hashalg;

	/*
	 * Salt specification for RSA PSS
	 * required: only for PSS
	 */
	enum saltlen saltlen;

	/*
	 * Length of the PSS salt in bytes.
	 *
	 * This field is only evaluated if saltlen is set to
	 * DEF_ALG_RSA_PSS_SALT_VALUE.
	 * required: optional, only for PSS
	 */
	int saltlen_bytes;
};

struct def_algo_rsa_sigver_gen {
	/*
	 * Supports fixed or random public key exponent e
	 * required: always
	 */
	enum pubexpmode pubexpmode;

	/*
	 * The value of the public key exponent e in hex
	 *
	 * required: only if DEF_ALG_RSA_PUBEXTMODE_FIXED is selected in
	 * pubexpmode.
	 */
	const char *fixedpubexp;
};

struct def_algo_rsa_sigver {
	/*
	 * RSA signature types - see [FIPS140-2] section 5
	 *
	 * required: always
	 */
	enum sigtype sigtype;

	/*
	 * Capabilities for this sigType - see [FIPS186-4] section 5
	 *
	 * required: always
	 */
	const struct def_algo_rsa_sigver_caps *capabilities;

	/*
	 * Number of capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int capabilities_num;
};

/****************************************************************************
 * RSA component signature specific data
 ****************************************************************************/
struct def_algo_rsa_component_sig_gen {
	/*
	 * The preferred private key format. The DEF_ALG_RSA_KEYFORMAT_STANDARD
	 * format has "p", "q", and "d" as the component of the private key.
	 * The DEF_ALG_RSA_KEYFORMAT_CRT (Chinese Remainder Theorem) format has
	 * "p", "q", "dmp1" (d modulo p-1), "dmq1" (d modulo q-1), and "iqmp"
	 * (inverse q modulo p)) as the components
	 *
	 * required: always
	 */
	enum keyformat keyformat;
};

/****************************************************************************
 * RSA component decryption specific data
 ****************************************************************************/
struct def_algo_rsa_component_dec {
	/*
	 * Supported RSA modulo for the decryption primitive
	 *
	 * required: always
	 */
	enum rsa_modulo rsa_modulo;
};

/****************************************************************************
 * RSA common data data
 ****************************************************************************/
struct def_algo_rsa {

	/*
	 * RSA mode type
	 * required: always
	 */
	enum rsa_mode {
		DEF_ALG_RSA_MODE_KEYGEN,
		DEF_ALG_RSA_MODE_SIGGEN,
		DEF_ALG_RSA_MODE_SIGVER,
		DEF_ALG_RSA_MODE_LEGACY_SIGVER,
		DEF_ALG_RSA_MODE_COMPONENT_SIG_PRIMITIVE,
		DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE,
	} rsa_mode;

	/*
	 * Prerequisites to RSA
	 * required: always
	 * SHA
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
	 * General information about the cipher request
	 *
	 * required for:
	 * * RSA key generation
	 * * RSA signature verification
	 * * RSA component signature
	 * * RSA component decryption
	 */
	union {
		const struct def_algo_rsa_keygen_gen *keygen;
		const struct def_algo_rsa_sigver_gen *sigver;
		const struct def_algo_rsa_component_sig_gen *component_sig;
	} gen_info;

	/*
	 * Specific cipher request information. One or more instances of the
	 * following structure are allowed. If multiple instances are used,
	 * they must all be allocated adjacent in memory and the @param
	 * algspecs_num variable must indicate the number of instances.
	 *
	 * required: always
	 */
	union {
		const struct def_algo_rsa_keygen *keygen;
		const struct def_algo_rsa_siggen *siggen;
		const struct def_algo_rsa_sigver *sigver;
		const struct def_algo_rsa_component_dec *component_dec;
	} algspecs;

	/*
	 * Number of algspecs, if 0, no entry is added to JSON
	 * Note, the algspecs pointer above must point to the first
	 * entry of an array of schemes!
	 */
	unsigned int algspecs_num;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_RSA_H */
