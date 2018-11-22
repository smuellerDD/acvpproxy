/* JSON generator for RSA ciphers
 *
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

static int acvp_req_rsa_modulo(enum rsa_mode rsa_mode, enum rsa_modulo modulo,
			       struct json_object *entry)
{
	int ret = 0;

	switch(modulo) {
	case DEF_ALG_RSA_MODULO_1024:
		if (rsa_mode != DEF_ALG_RSA_MODE_SIGVER &&
		    rsa_mode != DEF_ALG_RSA_MODE_LEGACY_SIGVER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "RSA modulo 1024 only allowed for (legacy and regulars) signature verification\n");
			return -EINVAL;
		}
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(1024)));
		break;
	case DEF_ALG_RSA_MODULO_2048:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(2048)));
		break;
	case DEF_ALG_RSA_MODULO_3072:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(3072)));
		break;
	case DEF_ALG_RSA_MODULO_4096:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(4096)));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA modulo definition\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int acvp_req_rsa_pubexpmode(enum pubexpmode pubexpmode,
				   const char *fixedpubexp,
				   struct json_object *entry)
{
	int ret = 0;

	switch (pubexpmode) {
	case DEF_ALG_RSA_PUBEXTMODE_FIXED:
		CKINT(json_object_object_add(entry, "pubExpMode",
					     json_object_new_string("fixed")));
		if (!fixedpubexp) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "fixedPubExp not defined\n");
			return -EINVAL;
		}
		CKINT(json_object_object_add(entry, "fixedPubExp",
					json_object_new_string(fixedpubexp)));
		break;
	case DEF_ALG_RSA_PUBEXTMODE_RANDOM:
		CKINT(json_object_object_add(entry, "pubExpMode",
					     json_object_new_string("random")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA pubExpMode definition\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int acvp_req_rsa_add_sigtype(enum sigtype sigtype,
				    struct json_object *entry)
{
	int ret = 0;

	switch (sigtype) {
	case DEF_ALG_RSA_SIGTYPE_ANSIX931:
		CKINT(json_object_object_add(entry, "sigType",
					json_object_new_string("ansx9.31")));
		break;
	case DEF_ALG_RSA_SIGTYPE_PKCS1V15:
		CKINT(json_object_object_add(entry, "sigType",
					json_object_new_string("pkcs1v1.5")));
		break;
	case DEF_ALG_RSA_SIGTYPE_PSS:
		CKINT(json_object_object_add(entry, "sigType",
					     json_object_new_string("pss")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA sigType definition\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int acvp_req_rsa_hashalg(cipher_t hashalg,
				struct json_object *entry, enum saltlen saltlen)
{
	struct json_object *hash_array;
	unsigned int i;
	int ret = 0;

	hash_array = json_object_new_array();
	CKNULL(hash_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "hashPair", hash_array));

	for (i = 0; i < ARRAY_SIZE(cipher_def_map); i++) {
		if ((hashalg & ACVP_HASHMASK) &
		     ((cipher_def_map[i].cipher) & ACVP_HASHMASK) &&
		    (hashalg & ACVP_CIPHERDEF) &
		     ((cipher_def_map[i].cipher) & ACVP_CIPHERDEF)) {

			const char *algo = cipher_def_map[i].acvp_name;
			struct json_object *tmp = json_object_new_object();

			CKNULL(tmp, -ENOMEM);
			CKINT(json_object_array_add(hash_array, tmp));

			CKINT(json_object_object_add(tmp, "hashAlg",
						json_object_new_string(algo)));

			if (saltlen == DEF_ALG_RSA_PSS_SALT_ZERO) {
				CKINT(json_object_object_add(tmp, "saltLen",
						json_object_new_int(0)));
			} else if (saltlen == DEF_ALG_RSA_PSS_SALT_HASHLEN) {
				unsigned int hashlen;

				if (!strncmp(algo, "SHA2-224", 8))
					hashlen = 28;
				else if (!strncmp(algo, "SHA2-256", 8))
					hashlen = 32;
				else if (!strncmp(algo, "SHA2-384", 8))
					hashlen = 48;
				else if (!strncmp(algo, "SHA2-512/224", 12))
					hashlen = 28;
				else if (!strncmp(algo, "SHA2-512/256", 12))
					hashlen = 32;
				else if (!strncmp(algo, "SHA2-512", 8))
					hashlen = 64;
				else {
					logger(LOGGER_WARN, LOGGER_C_ANY,
					       "Unknown hash value %s\n", algo);
					ret = -EINVAL;
					goto out;
				}

				CKINT(json_object_object_add(tmp, "saltLen",
						json_object_new_int(hashlen)));
			}
		}
	}

out:
	return ret;
}

static int acvp_req_rsa_keygen_caps(enum rsa_mode rsa_mode,
				    enum rsa_randpq rsa_randpq,
				    const struct def_algo_rsa_keygen_caps *caps,
				    struct json_object *caps_entry)
{
	struct json_object *prime_array;
	int ret = 0;

	CKINT(acvp_req_rsa_modulo(rsa_mode, caps->rsa_modulo, caps_entry));

	/* Hashes are not needed for probable primes */
	if (rsa_randpq != DEF_ALG_RSA_PQ_B33_PRIMES) {
		CKINT(acvp_req_cipher_to_array(caps_entry, caps->hashalg,
					       ACVP_CIPHERTYPE_HASH,
					       "hashAlg"));
	}

	prime_array = json_object_new_array();
	CKNULL(prime_array, -ENOMEM);
	CKINT(json_object_object_add(caps_entry, "primeTest", prime_array));

	if (caps->rsa_primetest & DEF_ALG_RSA_PRIMETEST_C2) {
		CKINT(json_object_array_add(prime_array,
					    json_object_new_string("tblC2")));
	}
	if (caps->rsa_primetest & DEF_ALG_RSA_PRIMETEST_C3) {
		CKINT(json_object_array_add(prime_array,
					    json_object_new_string("tblC3")));
	}

out:
	return ret;
}

static int _acvp_req_rsa_keygen(enum rsa_mode rsa_mode,
				const struct def_algo_rsa_keygen *keygen,
			        struct json_object *algspec)
{
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	switch (keygen->rsa_randpq) {
	case DEF_ALG_RSA_PQ_B32_PRIMES:
		CKINT(json_object_object_add(algspec, "randPQ",
					     json_object_new_string("B.3.2")));
		break;
	case DEF_ALG_RSA_PQ_B33_PRIMES:
		CKINT(json_object_object_add(algspec, "randPQ",
					     json_object_new_string("B.3.3")));
		break;
	case DEF_ALG_RSA_PQ_B34_PRIMES:
		CKINT(json_object_object_add(algspec, "randPQ",
					     json_object_new_string("B.3.4")));
		break;
	case DEF_ALG_RSA_PQ_B35_PRIMES:
		CKINT(json_object_object_add(algspec, "randPQ",
					     json_object_new_string("B.3.5")));
		break;
	case DEF_ALG_RSA_PQ_B36_PRIMES:
		CKINT(json_object_object_add(algspec, "randPQ",
					     json_object_new_string("B.3.6")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA randPQ definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(algspec, "properties", caps_array));

	for (i = 0; i < keygen->capabilities_num; i++) {
		const struct def_algo_rsa_keygen_caps *caps =
						keygen->capabilities + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_rsa_keygen_caps(rsa_mode, keygen->rsa_randpq,
					       caps, caps_entry));
	}

out:
	return ret;
}

static int acvp_req_rsa_keygen(const struct def_algo_rsa *rsa,
			       struct json_object *entry)
{
	const struct def_algo_rsa_keygen_gen *gen = rsa->gen_info.keygen;
	struct json_object *algspec_array, *algspec;
	unsigned int i;
	int ret;

	CKINT(json_object_object_add(entry, "infoGeneratedByServer",
			json_object_new_boolean(gen->infogeneratedbyserver)));
	CKINT(acvp_req_rsa_pubexpmode(gen->pubexpmode, gen->fixedpubexp,
				      entry));

	switch (gen->keyformat) {
	case DEF_ALG_RSA_KEYFORMAT_STANDARD:
		CKINT(json_object_object_add(entry, "keyFormat",
					json_object_new_string("standard")));
		break;
	case DEF_ALG_RSA_KEYFORMAT_CRT:
		CKINT(json_object_object_add(entry, "keyFormat",
					json_object_new_string("crt")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA keyFormat definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	algspec_array = json_object_new_array();
	CKNULL(algspec_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", algspec_array));

	for (i = 0; i < rsa->algspecs_num; i++) {
		const struct def_algo_rsa_keygen *keygen =
						rsa->algspecs.keygen + i;

		algspec = json_object_new_object();
		CKNULL(algspec, -ENOMEM);
		CKINT(json_object_array_add(algspec_array, algspec));
		CKINT(_acvp_req_rsa_keygen(rsa->rsa_mode, keygen, algspec));
	}

out:
	return ret;
}

static int acvp_req_rsa_siggen_caps(enum rsa_mode rsa_mode,
				    const struct def_algo_rsa_siggen_caps *caps,
				    struct json_object *caps_entry,
				    enum saltlen saltlen)
{
	int ret = 0;

	CKINT(acvp_req_rsa_modulo(rsa_mode, caps->rsa_modulo, caps_entry));
	CKINT(acvp_req_rsa_hashalg(caps->hashalg, caps_entry, saltlen));

out:
	return ret;
}

static int _acvp_req_rsa_siggen(enum rsa_mode rsa_mode,
				const struct def_algo_rsa_siggen *siggen,
			        struct json_object *algspec)
{
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	CKINT(acvp_req_rsa_add_sigtype(siggen->sigtype, algspec));

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(algspec, "properties",
				     caps_array));

	for (i = 0; i < siggen->capabilities_num; i++) {
		const struct def_algo_rsa_siggen_caps *caps =
						siggen->capabilities + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_rsa_siggen_caps(rsa_mode, caps, caps_entry,
					       caps->saltlen));
	}

out:
	return ret;
}

static int acvp_req_rsa_siggen(const struct def_algo_rsa *rsa,
			       struct json_object *entry)
{
	struct json_object *algspec_array, *algspec;
	unsigned int i;
	int ret = 0;

	algspec_array = json_object_new_array();
	CKNULL(algspec_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", algspec_array));

	for (i = 0; i < rsa->algspecs_num; i++) {
		const struct def_algo_rsa_siggen *siggen =
						rsa->algspecs.siggen + i;

		algspec = json_object_new_object();
		CKNULL(algspec, -ENOMEM);
		CKINT(json_object_array_add(algspec_array, algspec));
		CKINT(_acvp_req_rsa_siggen(rsa->rsa_mode, siggen, algspec));
	}

out:
	return ret;
}

static int acvp_req_rsa_sigver_caps(enum rsa_mode rsa_mode,
				    const struct def_algo_rsa_sigver_caps *caps,
				    struct json_object *caps_entry,
				    enum saltlen saltlen)
{
	int ret = 0;

	CKINT(acvp_req_rsa_modulo(rsa_mode, caps->rsa_modulo, caps_entry));
	CKINT(acvp_req_rsa_hashalg(caps->hashalg, caps_entry, saltlen));

out:
	return ret;
}

static int _acvp_req_rsa_sigver(enum rsa_mode rsa_mode,
				const struct def_algo_rsa_sigver *sigver,
			        struct json_object *algspec)
{
	struct json_object *caps_array, *caps_entry;
	unsigned int i;
	int ret = 0;

	CKINT(acvp_req_rsa_add_sigtype(sigver->sigtype, algspec));

	caps_array = json_object_new_array();
	CKNULL(caps_array, -ENOMEM);
	CKINT(json_object_object_add(algspec, "properties",
				     caps_array));

	for (i = 0; i < sigver->capabilities_num; i++) {
		const struct def_algo_rsa_sigver_caps *caps =
						sigver->capabilities + i;

		caps_entry = json_object_new_object();
		CKNULL(caps_entry, -ENOMEM);
		CKINT(json_object_array_add(caps_array, caps_entry));
		CKINT(acvp_req_rsa_sigver_caps(rsa_mode, caps, caps_entry,
					       caps->saltlen));
	}

out:
	return ret;
}

static int acvp_req_rsa_sigver(const struct def_algo_rsa *rsa,
			       struct json_object *entry)
{
	const struct def_algo_rsa_sigver_gen *sigver = rsa->gen_info.sigver;
	struct json_object *algspec_array, *algspec;
	unsigned int i;
	int ret;

	CKINT(acvp_req_rsa_pubexpmode(sigver->pubexpmode, sigver->fixedpubexp,
				      entry));

	algspec_array = json_object_new_array();
	CKNULL(algspec_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", algspec_array));

	for (i = 0; i < rsa->algspecs_num; i++) {
		const struct def_algo_rsa_sigver *sigver =
						rsa->algspecs.sigver + i;

		algspec = json_object_new_object();
		CKNULL(algspec, -ENOMEM);
		CKINT(json_object_array_add(algspec_array, algspec));
		CKINT(_acvp_req_rsa_sigver(rsa->rsa_mode, sigver, algspec));
	}

out:
	return ret;
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
int acvp_req_set_algo_rsa(const struct def_algo_rsa *rsa,
			  struct json_object *entry)
{
	int ret = -EINVAL;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("RSA")));

	switch (rsa->rsa_mode) {
	case DEF_ALG_RSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		CKINT(acvp_req_rsa_keygen(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		CKINT(acvp_req_rsa_siggen(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		CKINT(acvp_req_rsa_sigver(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_LEGACY_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					json_object_new_string("legacySigVer")));
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_SIG_PRIMITIVE:
		CKINT(json_object_object_add(entry, "mode",
			json_object_new_string("componentSigPrimitive")));
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE:
		CKINT(json_object_object_add(entry, "mode",
			json_object_new_string("componentDecPrimitive")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unknown RSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_gen_prereq(rsa->prereqvals, rsa->prereqvals_num,
				  entry));


	return 0;

out:
	return ret;
}
