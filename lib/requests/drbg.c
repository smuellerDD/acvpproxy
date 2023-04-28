/* JSON request generator for SP800-90A DRBG
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

struct acvp_req_drbg_range {
	unsigned int min;
	unsigned int max;
	unsigned int step;
};

struct acvp_req_drbg_limits {
	cipher_t cipher;
	bool df;
	struct acvp_req_drbg_range entropy;
	struct acvp_req_drbg_range perso;
	struct acvp_req_drbg_range addtl;
	struct acvp_req_drbg_range nonce;
};

const struct acvp_req_drbg_limits drbg_limits[] = {
	{ ACVP_AES128, false,		{ 256, 256, 8 },	{ 0, 256, 8 },		{ 0, 256, 8 },		{ 0, INT_MAX, 8 }, },
	{ ACVP_AES128, true,		{ 128, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 64, INT_MAX, 8 }, },

	{ ACVP_AES192, false,		{ 320, 320, 8 },	{ 0, 320, 8 },		{ 0, 320, 8 },		{ 0, INT_MAX, 8 }, },
	{ ACVP_AES192, true,		{ 192, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 96, INT_MAX, 8 }, },

	{ ACVP_AES256, false,		{ 384, 384, 8 },	{ 0, 384, 8 },		{ 0, 384, 8 },		{ 0, INT_MAX, 8 }, },
	{ ACVP_AES256, true,		{ 256, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },

	{ ACVP_TDES, true,		{ 112, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 56, INT_MAX, 8 }, },
	{ ACVP_TDES, false,		{ 112, 232, 8 },	{ 0, 232, 8 },		{ 0, 232, 8 },		{ 0, INT_MAX, 8 }, },

	{ ACVP_SHA1, false,		{ 80, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 40, INT_MAX, 8 }, },
	{ ACVP_SHA224, false,		{ 112, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 56, INT_MAX, 8 }, },
	{ ACVP_SHA256, false,		{ 128, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 64, INT_MAX, 8 }, },
	{ ACVP_SHA384, false,		{ 192, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 96, INT_MAX, 8 }, },
	{ ACVP_SHA512, false,		{ 256, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },
	{ ACVP_SHA512224, false,	{ 112, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 56, INT_MAX, 8 }, },
	{ ACVP_SHA512256, false,	{ 128, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 64, INT_MAX, 8 }, },

	{ ACVP_HMACSHA1, false,		{ 128, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 64, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_224, false,	{ 192, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 96, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_256, false,	{ 256, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_384, false,	{ 192, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_512, false,	{ 256, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_512224, false,	{ 192, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 96, INT_MAX, 8 }, },
	{ ACVP_HMACSHA2_512256, false,	{ 128, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 0, INT_MAX, 8 },	{ 128, INT_MAX, 8 }, },
};

static int acvp_req_drbg_check(const struct def_algo_drbg_caps *caps)
{
	unsigned int i;
	int ret = 0;
	bool found = false;

	for (i = 0; i < ARRAY_SIZE(drbg_limits); i++) {
		const char *algo;
		/* Match entry */
		if (caps->mode != drbg_limits[i].cipher)
			continue;

		/* Match DF */
		if ((caps->mode & (ACVP_CIPHERTYPE_AES)) &&
		    caps->df != drbg_limits[i].df)
			continue;

		found = true;

		CKINT(acvp_req_cipher_to_name(caps->mode,
			(ACVP_CIPHERTYPE_AES | ACVP_CIPHERTYPE_HASH |
			 ACVP_CIPHERTYPE_TDES), &algo));
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "DRBG checking DRBG definition %s\n", algo);

		CKINT_LOG(acvp_req_valid_range(drbg_limits[i].entropy.min,
					       drbg_limits[i].entropy.max,
					       drbg_limits[i].entropy.step,
					       caps->entropyinputlen),
			  "DRBG: Entropy length outside of allowed range (%u - %u, step %u)\n",
			  drbg_limits[i].entropy.min, drbg_limits[i].entropy.max,
			  drbg_limits[i].entropy.step);

		CKINT_LOG(acvp_req_valid_range(drbg_limits[i].perso.min,
					       drbg_limits[i].perso.max,
					       drbg_limits[i].perso.step,
					       caps->persostringlen),
			  "DRBG: Personalization string length outside of allowed range (%u - %u, step %u)\n",
			  drbg_limits[i].perso.min, drbg_limits[i].perso.max,
			  drbg_limits[i].perso.step);
		CKINT_LOG(acvp_req_valid_range(drbg_limits[i].addtl.min,
					       drbg_limits[i].addtl.max,
					       drbg_limits[i].addtl.step,
					       caps->additionalinputlen),
			  "DRBG: Additional info string length outside of allowed range (%u - %u, step %u)\n",
			  drbg_limits[i].addtl.min, drbg_limits[i].addtl.max,
			  drbg_limits[i].addtl.step);
		CKINT_LOG(acvp_req_valid_range(drbg_limits[i].nonce.min,
					       drbg_limits[i].nonce.max,
					       drbg_limits[i].nonce.step,
					       caps->noncelen),
			  "DRBG: Nonce length outside of allowed range (%u - %u, step %u)\n",
			  drbg_limits[i].nonce.min, drbg_limits[i].nonce.max,
			  drbg_limits[i].nonce.step);

		break;
	}

	if (!found) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "DRBG: Unknown DRBG type\n");
		return -EINVAL;
	}

out:
	return ret;
}

int acvp_list_algo_drbg(const struct def_algo_drbg *drbg,
		        struct acvp_list_ciphers **new)
{
	const struct def_algo_drbg_caps *caps = drbg->capabilities;
	struct acvp_list_ciphers *tmp;
	char buf[FILENAME_MAX];
	unsigned int i, idx = 0;
	int ret;
	bool aes128 = false, aes192 = false, aes256 = false, tdes = false;

	memset(buf, 0, sizeof(buf));

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, drbg->algorithm));

	for (i = 0; i < drbg->num_caps; i++) {
		if ((caps->mode == ACVP_AES128 ||
		     caps->mode == ACVP_AES192 ||
		     caps->mode == ACVP_AES256) &&
		     (!aes128 && !aes192 && !aes256)) {
			if (strlen(buf))
				CKINT(acvp_extend_string(buf, sizeof(buf),
							 ", "));
			CKINT(acvp_extend_string(buf, sizeof(buf), "AES"));
		}

		if (caps->mode == ACVP_AES128 && !aes128) {
			tmp->keylen[idx++] = 128;
			aes128 = true;
			if (idx >= DEF_ALG_MAX_INT)
				goto out;
		}
		if (caps->mode == ACVP_AES192 && !aes192) {
			tmp->keylen[idx++] = 192;
			aes192 = true;
			if (idx >= DEF_ALG_MAX_INT)
				goto out;
		}
		if (caps->mode == ACVP_AES256 && !aes256) {
			tmp->keylen[idx++] = 256;
			aes256 = true;
			if (idx >= DEF_ALG_MAX_INT)
				goto out;
		}
		if (caps->mode == ACVP_TDES && !tdes) {
			if (strlen(buf))
				CKINT(acvp_extend_string(buf, sizeof(buf),
							 ", "));
			CKINT(acvp_extend_string(buf, sizeof(buf), "TDES"));

			tmp->keylen[idx++] = 168;
			tdes = true;
			if (idx >= DEF_ALG_MAX_INT)
				goto out;
		}

		if (caps->mode & ACVP_CIPHERTYPE_HASH) {
			const char *algo;

			if (strlen(buf))
				CKINT(acvp_extend_string(buf, sizeof(buf),
							 ", "));

			CKINT(acvp_req_cipher_to_name(caps->mode,
						      ACVP_CIPHERTYPE_HASH,
						      &algo));
			CKINT(acvp_extend_string(buf, sizeof(buf), algo));
		}

		caps++;
	}

	if (idx < DEF_ALG_MAX_INT)
		tmp->keylen[idx] = DEF_ALG_ZERO_VALUE;

	CKINT(acvp_duplicate(&tmp->cipher_aux, buf));

	tmp->prereqs = drbg->prereqvals;
	tmp->prereq_num = drbg->prereqvals_num;

out:
	return ret;
}

int acvp_req_set_prereq_drbg(const struct def_algo_drbg *drbg,
			     const struct acvp_test_deps *deps,
			     struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string(drbg->algorithm)));

	CKINT(acvp_req_gen_prereq(drbg->prereqvals, drbg->prereqvals_num, deps,
				  entry, publish));

out:
	return ret;
}

/*
 * Generate algorithm entry for DRBG
 */
int acvp_req_set_algo_drbg(const struct def_algo_drbg *drbg,
			   struct json_object *entry)
{
	const struct def_algo_drbg_caps *caps = drbg->capabilities;
	struct json_object *tmp_array = NULL;
	unsigned int i;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_drbg(drbg, NULL, entry, false));

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	if (drbg->pr & DEF_ALG_DRBG_PR_DISABLED)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(false)));
	if (drbg->pr & DEF_ALG_DRBG_PR_ENABLED)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_boolean(true)));
	CKINT(json_object_object_add(entry, "predResistanceEnabled",
				     tmp_array));

	CKINT(json_object_object_add(entry, "reseedImplemented",
				     json_object_new_boolean(drbg->reseed)));

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	for (i = 0; i < drbg->num_caps; i++) {
		struct json_object *cap_entry = json_object_new_object();

		CKNULL(cap_entry, -ENOMEM);

		CKINT(acvp_req_cipher_to_string(cap_entry, caps->mode,
						ACVP_CIPHERTYPE_HASH |
						ACVP_CIPHERTYPE_AES |
						ACVP_CIPHERTYPE_TDES,
						"mode"));

		CKINT(json_object_object_add(cap_entry, "derFuncEnabled",
					json_object_new_boolean(caps->df)));

		CKINT(acvp_req_drbg_check(caps));

		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->entropyinputlen,
						     "entropyInputLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->noncelen,
						     "nonceLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->persostringlen,
						     "persoStringLen"));
		CKINT(acvp_req_algo_int_array_always(cap_entry,
						     caps->additionalinputlen,
						     "additionalInputLen"));

		CKINT(json_object_object_add(cap_entry, "returnedBitsLen",
			       json_object_new_int(caps->returnedbitslen)));

		CKINT(json_object_array_add(tmp_array, cap_entry));

		caps++;
	}

	CKINT(json_object_object_add(entry, "capabilities", tmp_array));
	tmp_array = NULL;

	ret = 0;

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}
