/* JSON generator for RSA ciphers
 *
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

	switch (modulo) {
	case DEF_ALG_RSA_MODULO_1024:
		if (rsa_mode != DEF_ALG_RSA_MODE_SIGVER &&
		    rsa_mode != DEF_ALG_RSA_MODE_LEGACY_SIGVER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "RSA: modulo 1024 only allowed for (legacy and regulars) signature verification\n");
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
	case DEF_ALG_RSA_MODULO_5120:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(5120)));
		break;
	case DEF_ALG_RSA_MODULO_6144:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(6144)));
		break;
	case DEF_ALG_RSA_MODULO_7168:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(7168)));
		break;
	case DEF_ALG_RSA_MODULO_8192:
		CKINT(json_object_object_add(entry, "modulo",
					     json_object_new_int(8192)));
		break;
	case DEF_ALG_RSA_MODULO_UNDEF:
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA modulo definition\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int acvp_req_rsa_modulo_list(enum rsa_modulo modulo, cipher_t *keylen)
{
	int ret = 0;

	switch (modulo) {
	case DEF_ALG_RSA_MODULO_1024:
		*keylen = 1024;
		break;
	case DEF_ALG_RSA_MODULO_2048:
		*keylen = 2048;
		break;
	case DEF_ALG_RSA_MODULO_3072:
		*keylen = 3072;
		break;
	case DEF_ALG_RSA_MODULO_4096:
		*keylen = 4096;
		break;
	case DEF_ALG_RSA_MODULO_5120:
		*keylen = 5120;
		break;
	case DEF_ALG_RSA_MODULO_6144:
		*keylen = 6144;
		break;
	case DEF_ALG_RSA_MODULO_7168:
		*keylen = 7168;
		break;
	case DEF_ALG_RSA_MODULO_8192:
		*keylen = 8192;
		break;
	case DEF_ALG_RSA_MODULO_UNDEF:
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA modulo definition\n");
		return -EINVAL;
	}

	return ret;
}

static int acvp_req_rsa_sigtype_list(enum sigtype sigtype, const char **name)
{
	int ret = 0;

	switch (sigtype) {
	case DEF_ALG_RSA_SIGTYPE_ANSIX931:
		*name = "ANSIX931";
		break;
	case DEF_ALG_RSA_SIGTYPE_PKCS1V15:
		*name = "PKCS1v1.5";
		break;
	case DEF_ALG_RSA_SIGTYPE_PSS:
		*name = "PSS";
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA signature type definition\n");
		return -EINVAL;
	}

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
			       "RSA: fixedPubExp not defined\n");
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
		       "RSA: Unknown RSA pubExpMode definition\n");
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
		       "RSA: Unknown RSA sigType definition\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int acvp_req_rsa_hashalg(cipher_t hashalg, enum rsa_modulo modulo,
				struct json_object *entry, enum saltlen saltlen,
				int saltlen_bytes)
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
				int hashlen;

				if (!strncmp(algo, "SHA-1", 8))
					hashlen = 20;
				else if (!strncmp(algo, "SHA2-224", 8))
					hashlen = 28;
				else if (!strncmp(algo, "SHA2-256", 8))
					hashlen = 32;
				else if (!strncmp(algo, "SHA2-384", 8))
					hashlen = 48;
				else if (!strncmp(algo, "SHA2-512/224", 12))
					hashlen = 28;
				else if (!strncmp(algo, "SHA2-512/256", 12))
					hashlen = 32;
				else if (!strncmp(algo, "SHA2-512", 8)) {
					/* FIPS 186-4 section 5.5 bullet (e) */
					if (modulo == DEF_ALG_RSA_MODULO_1024)
						hashlen = 62;
					else
						hashlen = 64;
				} else {
					logger(LOGGER_WARN, LOGGER_C_ANY,
					       "RSA: Unknown hash value %s\n", algo);
					ret = -EINVAL;
					goto out;
				}

				CKINT(json_object_object_add(tmp, "saltLen",
						json_object_new_int(hashlen)));
			} else if (saltlen == DEF_ALG_RSA_PSS_SALT_VALUE) {
				CKINT(json_object_object_add(tmp, "saltLen",
					json_object_new_int(saltlen_bytes)));
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
		       "RSA: Unknown RSA randPQ definition\n");
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

static int acvp_req_rsa_keyformat(enum keyformat keyformat,
				  struct json_object *entry)
{
	int ret;

	switch (keyformat) {
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
		       "RSA: Unknown RSA keyFormat definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

out:
	return ret;
}

static int acvp_req_rsa_keyformat_list(enum keyformat keyformat,
				       const char **name)
{
	int ret = 0;

	switch (keyformat) {
	case DEF_ALG_RSA_KEYFORMAT_STANDARD:
		*name = "standard";
		break;
	case DEF_ALG_RSA_KEYFORMAT_CRT:
		*name = "crt";
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA keyFormat definition\n");
		ret = -EINVAL;
		goto out;
		break;
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

	CKINT(acvp_req_rsa_keyformat(gen->keyformat, entry));

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
				    enum saltlen saltlen,
				    int saltlen_bytes)
{
	int ret = 0;

	CKINT(acvp_req_rsa_modulo(rsa_mode, caps->rsa_modulo, caps_entry));
	CKINT(acvp_req_rsa_hashalg(caps->hashalg, caps->rsa_modulo, caps_entry,
				   saltlen, saltlen_bytes));

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

		if (siggen->sigtype == DEF_ALG_RSA_SIGTYPE_PSS &&
		    caps->saltlen == DEF_ALG_RSA_PSS_SALT_IGNORE) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "RSA: PSS siggen requires a salt value\n");
			return -EINVAL;
		}

		if (siggen->sigtype == DEF_ALG_RSA_SIGTYPE_PSS) {
			CKINT(acvp_req_rsa_siggen_caps(rsa_mode, caps,
				caps_entry, caps->saltlen,
				caps->saltlen_bytes));
		} else {
			CKINT(acvp_req_rsa_siggen_caps(rsa_mode, caps,
				caps_entry, DEF_ALG_RSA_PSS_SALT_IGNORE, 0));
		}
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
				    enum saltlen saltlen,
				    int saltlen_bytes)
{
	int ret = 0;

	CKINT(acvp_req_rsa_modulo(rsa_mode, caps->rsa_modulo, caps_entry));
	CKINT(acvp_req_rsa_hashalg(caps->hashalg, caps->rsa_modulo, caps_entry,
				   saltlen, saltlen_bytes));

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
					       caps->saltlen,
					       caps->saltlen_bytes));
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
		const struct def_algo_rsa_sigver *s =
						rsa->algspecs.sigver + i;

		algspec = json_object_new_object();
		CKNULL(algspec, -ENOMEM);
		CKINT(json_object_array_add(algspec_array, algspec));
		CKINT(_acvp_req_rsa_sigver(rsa->rsa_mode, s, algspec));
	}

out:
	return ret;
}

//TODO final JSON structure pending on decision of issue 539
static int acvp_req_rsa_component_dec(const struct def_algo_rsa *rsa,
				      struct json_object *entry)
{
	struct json_object *algspec_array, *algspec;
	unsigned int i;
	int ret;

	algspec_array = json_object_new_array();
	CKNULL(algspec_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", algspec_array));

	for (i = 0; i < rsa->algspecs_num; i++) {
		const struct def_algo_rsa_component_dec *component_dec =
						rsa->algspecs.component_dec + i;

		algspec = json_object_new_object();
		CKNULL(algspec, -ENOMEM);
		CKINT(json_object_array_add(algspec_array, algspec));
		CKINT(acvp_req_rsa_modulo(
			DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE,
			component_dec->rsa_modulo, algspec));
	}

out:
	return ret;
}

/*
 * Generate algorithm entry for symmetric ciphers
 */
static int _acvp_req_set_algo_rsa(const struct def_algo_rsa *rsa,
				  const struct acvp_test_deps *deps,
				  struct json_object *entry, bool full,
				  bool publish)
{
	const struct def_algo_rsa_component_sig_gen *component_sig;
	int ret = -EINVAL;

	if (full) {
		switch (rsa->rsa_mode) {
		case DEF_ALG_RSA_MODE_KEYGEN:
		case DEF_ALG_RSA_MODE_SIGGEN:
		case DEF_ALG_RSA_MODE_SIGVER:
			CKINT(acvp_req_add_revision(entry, "FIPS186-4"));
			break;
		case DEF_ALG_RSA_MODE_COMPONENT_SIG_PRIMITIVE:
		case DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE:
			CKINT(acvp_req_add_revision(entry, "1.0"));
			break;
		case DEF_ALG_RSA_MODE_LEGACY_SIGVER:
			CKINT(acvp_req_add_revision(entry, "FIPS186-2"));
			break;
		default:
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "RSA: Unknown RSA keygen definition\n");
			ret = -EINVAL;
			goto out;
		break;
		}
	}

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("RSA")));

	switch (rsa->rsa_mode) {
	case DEF_ALG_RSA_MODE_KEYGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("keyGen")));
		if (full)
			CKINT(acvp_req_rsa_keygen(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_SIGGEN:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigGen")));
		if (full)
			CKINT(acvp_req_rsa_siggen(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
					     json_object_new_string("sigVer")));
		if (full)
			CKINT(acvp_req_rsa_sigver(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_LEGACY_SIGVER:
		CKINT(json_object_object_add(entry, "mode",
				json_object_new_string("legacySigVer")));
		if (full)
			CKINT(acvp_req_rsa_sigver(rsa, entry));
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_SIG_PRIMITIVE:
		component_sig = rsa->gen_info.component_sig;
		CKINT(json_object_object_add(entry, "mode",
			json_object_new_string("signaturePrimitive")));
		if (full)
			CKINT(acvp_req_rsa_keyformat(component_sig->keyformat,
						     entry));
		CKINT(acvp_req_rsa_pubexpmode(component_sig->pubexpmode,
					      component_sig->fixedpubexp,
					      entry));
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE:
		CKINT(json_object_object_add(entry, "mode",
			json_object_new_string("decryptionPrimitive")));
		if (full)
			CKINT(acvp_req_rsa_component_dec(rsa, entry));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(acvp_req_gen_prereq(rsa->prereqvals, rsa->prereqvals_num, deps,
				  entry, publish));

	return 0;

out:
	return ret;
}

int acvp_list_algo_rsa(const struct def_algo_rsa *rsa,
		       struct acvp_list_ciphers **new)
{
	const struct def_algo_rsa_component_sig_gen *component_sig;
	const char *name;
	char str[FILENAME_MAX];
	struct acvp_list_ciphers *tmp = NULL, *prev;
	unsigned int i, j, total = 0;
	cipher_t consolidated;
	int ret = 0;

	switch (rsa->rsa_mode) {
	case DEF_ALG_RSA_MODE_KEYGEN:
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		CKINT(acvp_duplicate(&tmp->cipher_name, "RSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "keyGen"));
		tmp->prereqs = rsa->prereqvals;
		tmp->prereq_num = rsa->prereqvals_num;

		consolidated = 0;
		for (i = 0; i < rsa->algspecs_num; i++) {
			const struct def_algo_rsa_keygen *keygen =
						rsa->algspecs.keygen + i;

			for (j = 0; j < keygen->capabilities_num; j++) {
				const struct def_algo_rsa_keygen_caps *caps =
						keygen->capabilities + j;

				if (total >= DEF_ALG_MAX_INT)
					break;

				CKINT(acvp_req_rsa_modulo_list(caps->rsa_modulo,
							&tmp->keylen[total++]));
				consolidated |= caps->hashalg;
			}

			if (total >= DEF_ALG_MAX_INT)
				break;
		}

		CKINT(acvp_req_cipher_to_stringarray(consolidated,
						     ACVP_CIPHERTYPE_HASH,
						     &tmp->cipher_aux));
		break;
	case DEF_ALG_RSA_MODE_SIGGEN:
		for (i = 0; i < rsa->algspecs_num; i++) {
			const struct def_algo_rsa_siggen *siggen =
						rsa->algspecs.siggen + i;
			const char *sigtype;

			memset(str, 0, sizeof(str));

			prev = tmp;
			tmp = calloc(1, sizeof(struct acvp_list_ciphers));
			CKNULL(tmp, -ENOMEM);
			tmp->next = prev;
			CKINT(acvp_duplicate(&tmp->cipher_name, "RSA"));

			CKINT(acvp_extend_string(str, sizeof(str), "sigGen"));
			tmp->prereqs = rsa->prereqvals;
			tmp->prereq_num = rsa->prereqvals_num;
			CKINT(acvp_req_rsa_sigtype_list(siggen->sigtype,
							&sigtype));
			CKINT(acvp_extend_string(str, sizeof(str), " - %s",
						 sigtype));
			CKINT(acvp_duplicate(&tmp->cipher_mode, str));

			total = 0;
			consolidated = 0;
			for (j = 0; j < siggen->capabilities_num; j++) {
				const struct def_algo_rsa_siggen_caps *caps =
						siggen->capabilities + j;

				if (total >= DEF_ALG_MAX_INT)
					break;

				CKINT(acvp_req_rsa_modulo_list(caps->rsa_modulo,
							&tmp->keylen[total++]));
				consolidated |= caps->hashalg;
			}

			CKINT(acvp_req_cipher_to_stringarray(consolidated,
				ACVP_CIPHERTYPE_HASH, &tmp->cipher_aux));

			if (total < DEF_ALG_MAX_INT)
				tmp->keylen[total] = DEF_ALG_ZERO_VALUE;
			else
				break;
		}
		break;
	case DEF_ALG_RSA_MODE_LEGACY_SIGVER:
	case DEF_ALG_RSA_MODE_SIGVER:
		for (i = 0; i < rsa->algspecs_num; i++) {
			const struct def_algo_rsa_sigver *sigver =
						rsa->algspecs.sigver + i;
			const char *sigtype;

			memset(str, 0, sizeof(str));

			prev = tmp;
			tmp = calloc(1, sizeof(struct acvp_list_ciphers));
			CKNULL(tmp, -ENOMEM);
			tmp->next = prev;
			CKINT(acvp_duplicate(&tmp->cipher_name, "RSA"));
			if (rsa->rsa_mode == DEF_ALG_RSA_MODE_SIGVER) {
				CKINT(acvp_extend_string(str, sizeof(str),
							 "sigVer"));
			} else {
				CKINT(acvp_extend_string(str, sizeof(str),
							 "legacySigVer"));
			}
			tmp->prereqs = rsa->prereqvals;
			tmp->prereq_num = rsa->prereqvals_num;

			CKINT(acvp_req_rsa_sigtype_list(sigver->sigtype,
							&sigtype));
			CKINT(acvp_extend_string(str, sizeof(str), " - %s",
						 sigtype));
			CKINT(acvp_duplicate(&tmp->cipher_mode, str));

			total = 0;
			consolidated = 0;
			for (j = 0; j < sigver->capabilities_num; j++) {
				const struct def_algo_rsa_sigver_caps *caps =
						sigver->capabilities + j;

				if (total >= DEF_ALG_MAX_INT)
					break;

				CKINT(acvp_req_rsa_modulo_list(caps->rsa_modulo,
							&tmp->keylen[total++]));
				consolidated |= caps->hashalg;
			}
			CKINT(acvp_req_cipher_to_stringarray(consolidated,
				ACVP_CIPHERTYPE_HASH, &tmp->cipher_aux));

			if (total < DEF_ALG_MAX_INT)
				tmp->keylen[total] = DEF_ALG_ZERO_VALUE;
			else
				break;
		}
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_SIG_PRIMITIVE:
		component_sig = rsa->gen_info.component_sig;
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		CKINT(acvp_duplicate(&tmp->cipher_name, "RSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "signaturePrimitive"));
		tmp->prereqs = rsa->prereqvals;
		tmp->prereq_num = rsa->prereqvals_num;
		CKINT(acvp_req_rsa_keyformat_list(component_sig->keyformat,
						  &name));
		CKINT(acvp_duplicate(&tmp->cipher_aux, name));
		tmp->keylen[0] = DEF_ALG_ZERO_VALUE;
		break;
	case DEF_ALG_RSA_MODE_COMPONENT_DEC_PRIMITIVE:
		tmp = calloc(1, sizeof(struct acvp_list_ciphers));
		CKNULL(tmp, -ENOMEM);
		CKINT(acvp_duplicate(&tmp->cipher_name, "RSA"));
		CKINT(acvp_duplicate(&tmp->cipher_mode, "decryptionPrimitive"));
		tmp->prereqs = rsa->prereqvals;
		tmp->prereq_num = rsa->prereqvals_num;
		for (i = 0; i < rsa->algspecs_num; i++) {
			const struct def_algo_rsa_component_dec *component_dec =
						rsa->algspecs.component_dec + i;

			CKINT(acvp_req_rsa_modulo_list(
						component_dec->rsa_modulo,
						&tmp->keylen[total++]));
		}
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "RSA: Unknown RSA keygen definition\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	if (tmp && total < DEF_ALG_MAX_INT)
		tmp->keylen[total] = DEF_ALG_ZERO_VALUE;

	/* in case of an error, we leak memory, but we do not care */
	*new = tmp;

out:
	return ret;
}

int acvp_req_set_prereq_rsa(const struct def_algo_rsa *rsa,
			    const struct acvp_test_deps *deps,
			    struct json_object *entry, bool publish)
{
	return _acvp_req_set_algo_rsa(rsa, deps, entry, false, publish);
}

int acvp_req_set_algo_rsa(const struct def_algo_rsa *rsa,
			  struct json_object *entry)
{
	return _acvp_req_set_algo_rsa(rsa, NULL, entry, true, false);
}

