/* ACVP proxy listing of cipher options
 *
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "internal.h"
#include "request_helper.h"

static void acvp_list_ciphers_free(struct acvp_list_ciphers *full_list)
{
	while (full_list) {
		struct acvp_list_ciphers *tmp = full_list;

		ACVP_PTR_FREE_NULL(full_list->cipher_mode);
		ACVP_PTR_FREE_NULL(full_list->cipher_name);
		ACVP_PTR_FREE_NULL(full_list->cipher_aux);
		ACVP_PTR_FREE_NULL(full_list->impl);
		ACVP_PTR_FREE_NULL(full_list->external_dep);
		ACVP_PTR_FREE_NULL(full_list->internal_dep);
		full_list = full_list->next;
		ACVP_PTR_FREE_NULL(tmp);
	}
}

static bool acvp_list_cipher_match_key(cipher_t dst[DEF_ALG_MAX_INT],
				       cipher_t src[DEF_ALG_MAX_INT])
{
	unsigned int i;

	for (i = 0; i < DEF_ALG_MAX_INT; i++) {
		if (src[DEF_ALG_MAX_INT] == DEF_ALG_ZERO_VALUE)
			break;

		if (src[i] != dst[i])
			return false;
	}

	return true;
}

static int
acvp_list_ciphers_store_sorted_one(struct acvp_list_ciphers **full_list,
				   struct acvp_list_ciphers *new)
{
	struct acvp_list_ciphers *list, *prev;
	int ret = 0;

	if (!*full_list) {
		*full_list = new;
		return 0;
	}

	/* Sorting */
	for (list = *full_list, prev = *full_list;
	     list != NULL;
	     list = list->next) {

		/* Remove duplicates */
		if (acvp_find_match(list->cipher_name, new->cipher_name,
				    false) &&
		    acvp_find_match(list->cipher_mode, new->cipher_mode,
				    false) &&
		    acvp_find_match(list->cipher_aux, new->cipher_aux,
				    false) &&
		    acvp_find_match(list->impl, new->impl, false) &&
		    acvp_find_match(list->internal_dep, new->internal_dep,
				    false) &&
		    acvp_find_match(list->external_dep, new->external_dep,
				    false) &&
		    acvp_list_cipher_match_key(list->keylen, new->keylen)) {
			acvp_list_ciphers_free(new);
			break;
		}

		/*
		 * Sort the key implementations for given certificate
		 * name in ascending order
		 */
		if (acvp_find_match(list->cipher_name,
				    new->cipher_name, false) &&
			(strncmp(list->impl, new->impl,
				 strlen(list->impl)) > 0)) {
			if (list == *full_list)
				*full_list = new;
			else
				prev->next = new;

			new->next = list;
			break;
		}

		/* Sort cipher name in ascending order. */
		if ((strncmp(list->cipher_name, new->cipher_name,
			     strlen(list->cipher_name)) > 0)) {
			if (list == *full_list)
				*full_list = new;
			else
				prev->next = new;

			new->next = list;
			break;
		}

		prev = list;

		/* We reached the end */
		if (!list->next) {
			list->next = new;
			break;
		}
	}

	return ret;
}

static int
acvp_list_ciphers_store_sorted(struct acvp_list_ciphers **full_list,
			       struct acvp_list_ciphers *new,
			       const char *impl, const char *internal_dep,
			       const char *external_dep)
{
	int ret = 0;

	while (new) {
		/*
		 * Store the next pointer as the current list entry pointers
		 * is changed
		 */
		struct acvp_list_ciphers *tmp = new->next;

		new->next = NULL;
		CKINT(acvp_duplicate(&new->impl, impl));
		CKINT(acvp_duplicate(&new->internal_dep, internal_dep));
		CKINT(acvp_duplicate(&new->external_dep, external_dep));
		CKINT(acvp_list_ciphers_store_sorted_one(full_list, new));

		new = tmp;
	}

out:
	return ret;
}

static int acvp_list_cipher_gatherer(const struct definition *def,
				     const struct def_algo *def_algo,
				     struct acvp_list_ciphers **full_list)
{
	const struct def_info *info = def->info;
	const struct def_deps *deps = def->deps;
	const struct def_algo_prereqs *prereqs;
	unsigned int prereq_num, i;
	struct acvp_list_ciphers *new = NULL;
	char internal_dep[FILENAME_MAX], external_dep[FILENAME_MAX],
	     impl[FILENAME_MAX];
	int ret;
	bool found = false, found2 = false;

	/* Gather the information from the different ciphers */
	switch(def_algo->type) {
	case DEF_ALG_TYPE_SYM:
		CKINT(acvp_list_algo_sym(&def_algo->algo.sym, &new));
		break;
	case DEF_ALG_TYPE_SHA:
		CKINT(acvp_list_algo_sha(&def_algo->algo.sha, &new));
		break;
	case DEF_ALG_TYPE_SHAKE:
		CKINT(acvp_list_algo_shake(&def_algo->algo.shake, &new));
		break;
	case DEF_ALG_TYPE_HMAC:
		CKINT(acvp_list_algo_hmac(&def_algo->algo.hmac, &new));
		break;
	case DEF_ALG_TYPE_CMAC:
		CKINT(acvp_list_algo_cmac(&def_algo->algo.cmac, &new));
		break;
	case DEF_ALG_TYPE_DRBG:
		CKINT(acvp_list_algo_drbg(&def_algo->algo.drbg, &new));
		break;
	case DEF_ALG_TYPE_RSA:
		CKINT(acvp_list_algo_rsa(&def_algo->algo.rsa, &new));
		break;
	case DEF_ALG_TYPE_ECDSA:
		CKINT(acvp_list_algo_ecdsa(&def_algo->algo.ecdsa, &new));
		break;
	case DEF_ALG_TYPE_EDDSA:
		CKINT(acvp_list_algo_eddsa(&def_algo->algo.eddsa, &new));
		break;
	case DEF_ALG_TYPE_DSA:
		CKINT(acvp_list_algo_dsa(&def_algo->algo.dsa, &new));
		break;
	case DEF_ALG_TYPE_KAS_ECC:
		CKINT(acvp_list_algo_kas_ecc(&def_algo->algo.kas_ecc, &new));
		break;
	case DEF_ALG_TYPE_KAS_FFC:
		CKINT(acvp_list_algo_kas_ffc(&def_algo->algo.kas_ffc, &new));
		break;
	case DEF_ALG_TYPE_KDF_SSH:
		CKINT(acvp_list_algo_kdf_ssh(&def_algo->algo.kdf_ssh, &new));
		break;
	case DEF_ALG_TYPE_KDF_IKEV1:
		CKINT(acvp_list_algo_kdf_ikev1(&def_algo->algo.kdf_ikev1,
					       &new));
		break;
	case DEF_ALG_TYPE_KDF_IKEV2:
		CKINT(acvp_list_algo_kdf_ikev2(&def_algo->algo.kdf_ikev2,
					       &new));
		break;
	case DEF_ALG_TYPE_KDF_TLS:
		CKINT(acvp_list_algo_kdf_tls(&def_algo->algo.kdf_tls, &new));
		break;
	case DEF_ALG_TYPE_KDF_108:
		CKINT(acvp_list_algo_kdf_108(&def_algo->algo.kdf_108, &new));
		break;
	case DEF_ALG_TYPE_PBKDF:
		CKINT(acvp_list_algo_pbkdf(&def_algo->algo.pbkdf, &new));
		break;
	case DEF_ALG_TYPE_KAS_FFC_R3:
		CKINT(acvp_list_algo_kas_ffc_r3(&def_algo->algo.kas_ffc_r3,
						&new));
		break;
	case DEF_ALG_TYPE_KAS_ECC_R3:
		CKINT(acvp_list_algo_kas_ecc_r3(&def_algo->algo.kas_ecc_r3,
						&new));
		break;
	case DEF_ALG_TYPE_SAFEPRIMES:
		CKINT(acvp_list_algo_safeprimes(&def_algo->algo.safeprimes,
						&new));
		break;
	case DEF_ALG_TYPE_KAS_IFC:
		CKINT(acvp_list_algo_kas_ifc(&def_algo->algo.kas_ifc, &new));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown algorithm definition type\n");
		ret = -EINVAL;
		goto out;
		return 0;
		break;
	}

	memset(&impl, 0, sizeof(impl));
	memset(&internal_dep, 0, sizeof(internal_dep));
	memset(&external_dep, 0, sizeof(external_dep));

	/* Perform dependency resolution */
	if (deps) {
		/* We have external dependencies */
		while (deps) {
			/* Manual external dependencies */
			if (deps->deps_type == acvp_deps_manual_resolution) {
				CKINT(acvp_extend_string(external_dep,
					sizeof(external_dep),
					"%s%s->%s",
					found ? ", " : "",
					deps->dep_cipher,
					deps->dep_name));
					found = true;
					continue;
			}

			if (!deps->dependency)
				continue;

			prereqs = new->prereqs;
			prereq_num = new->prereq_num;

			/*
			 * Iterate through all dependency types and point to
			 * the target dependencies.
			 */
			for (i = 0; i < prereq_num; i++, prereqs++) {
				if (acvp_find_match(deps->dep_cipher,
						     prereqs->algorithm,
						     false)) {
					/*
					 * Dependency to different test
					 * session.
					 */
					CKINT(acvp_extend_string(external_dep,
						sizeof(external_dep),
						"%s%s->%s",
						found ? ", " : "",
						deps->dep_cipher,
						deps->dependency->info->impl_name));
					found = true;
					break;
				} else {
					/*
					 * Dependency within our test session.
					 */
					CKINT(acvp_extend_string(internal_dep,
						 sizeof(internal_dep),
						 "%s->%s",
						 found2 ? ", " : "",
						 prereqs->algorithm));
					found2 = true;
				}
			}
			deps = deps->next;
		}
	}

	if (!found && !found2) {
		/*
		 * No external dependencies found, check whether we have only
		 * dependencies within our test session.
		 */
		prereqs = new->prereqs;
		prereq_num = new->prereq_num;
		for (i = 0; i < prereq_num; i++, prereqs++) {
			CKINT(acvp_extend_string(internal_dep,
						 sizeof(internal_dep),
						 "%s->%s",
						 found2 ? ", " : "",
						 prereqs->algorithm));
			found2 = true;
		}
	}

	if (!found && !found2) {
		/*
		 * We have no dependencies for our cipher, reference the
		 * implementation.
		 */
		CKINT(acvp_extend_string(impl, sizeof(impl),
					 "%s",
					 info->impl_name));
	}


	CKINT(acvp_list_ciphers_store_sorted(full_list, new, impl,
					     internal_dep, external_dep));

	return 0;

out:
	acvp_list_ciphers_free(new);
	return ret;
}

static int
acvp_list_cipher_options_prepare(const struct definition *def,
				 struct acvp_list_ciphers **full_list)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < def->num_algos; i++)
		CKINT(acvp_list_cipher_gatherer(def, def->algos + i,
						full_list));

out:
	return ret;
}

static void acvp_list_cipher_cpy_key(cipher_t dst[DEF_ALG_MAX_INT],
				     cipher_t src[DEF_ALG_MAX_INT])
{
	unsigned int i;

	for (i = 0; i < DEF_ALG_MAX_INT; i++)
		dst[i] = src[i];
}

static void acvp_list_cipher_maxlen(unsigned int *curr, const char *str)
{
	size_t stringlen;

	if (!str)
		return;

	stringlen = strlen(str);
	if (*curr < (unsigned int)stringlen)
		*curr = (unsigned int)stringlen;
}

static int acvp_list_cipher_key_to_str(cipher_t keylen[DEF_ALG_MAX_INT],
				       char *str, size_t stringlen)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < DEF_ALG_MAX_INT; i++) {
		if (keylen[i] == DEF_ALG_ZERO_VALUE)
			break;
		if (keylen[i] & ACVP_CIPHERTYPE) {
			const char *name;

			CKINT(acvp_req_cipher_to_name(keylen[i],
							0,
							&name));
			acvp_extend_string(str, stringlen, "%s, ", name);
		} else {
			acvp_extend_string(str, stringlen, "%lu, ", keylen[i]);
		}
	}

	/* remove last comma */
	if (i > 0)
		str[strlen(str) - 2] = '\0';

out:
	return ret;
}

static int
_acvp_list_cipher_options_print(struct acvp_list_ciphers *full_list,
				bool print_deps,
				unsigned int *ca_len, unsigned int *cm_len,
				unsigned int *cd_len, unsigned int *ks_len,
				unsigned int *im_len, unsigned int *ex_len,
				unsigned int *in_len)
{
	struct acvp_list_ciphers *list;
	const char *cipher_name = NULL, *cipher_mode = NULL, *cipher_aux = NULL;
	cipher_t  keylen[DEF_ALG_MAX_INT];
	char impl[FILENAME_MAX], external_dep[FILENAME_MAX],
	     internal_dep[FILENAME_MAX], tmp[FILENAME_MAX];
	int ret = 0;
	bool complete = true, print = true;

	/* We want only to generate the lengths */
	if (*ca_len == 0)
		print = false;

	memset(&impl, 0, sizeof(impl));
	memset(&internal_dep, 0, sizeof(internal_dep));
	memset(&external_dep, 0, sizeof(external_dep));

	for (list = full_list; list != NULL; list = list->next) {
		complete &= list->listed;

		/* Skip an already processed list entry */
		if (list->listed)
			goto nextloop;

		/* We have a fresh new cipher name */
		if (!cipher_name) {
			cipher_name = list->cipher_name;
			cipher_mode = list->cipher_mode;
			cipher_aux = list->cipher_aux;
			acvp_list_cipher_cpy_key(keylen, list->keylen);

			if (print)
				fprintf(stdout, "%-*s | ", *ca_len,
					cipher_name);
			else
				acvp_list_cipher_maxlen(ca_len, cipher_name);

			if (print)
				fprintf(stdout, "%-*s | ", *cm_len,
					cipher_mode ? cipher_mode : "");
			else
				acvp_list_cipher_maxlen(cm_len, cipher_mode);

			if (print)
				fprintf(stdout, "%-*s | ", *cd_len,
					cipher_aux ? cipher_aux : "");
			else
				acvp_list_cipher_maxlen(cd_len, cipher_aux);

			memset(tmp, 0, sizeof(tmp));
			CKINT(acvp_list_cipher_key_to_str(keylen, tmp,
							  sizeof(tmp)));

			if (print)
				fprintf(stdout, "%-*s%s", *ks_len, tmp,
					print_deps ? " | " : "");
			else
				acvp_list_cipher_maxlen(ks_len, tmp);

			if (print_deps) {
				acvp_extend_string(impl, sizeof(impl), "%s",
						   list->impl);
				acvp_extend_string(external_dep,
						   sizeof(external_dep),
						   "%s", list->external_dep);
				acvp_extend_string(internal_dep,
						   sizeof(internal_dep),
						   "%s", list->internal_dep);
			}

			list->listed = true;
			goto nextloop;
		}

		/* Only process entries with same cipher name / mode */
		if (!acvp_find_match(cipher_name, list->cipher_name,
				     false))
			goto nextloop;
		if (cipher_mode && !acvp_find_match(cipher_mode,
						    list->cipher_mode,
						    false))
			goto nextloop;

		if (cipher_aux && !acvp_find_match(cipher_aux,
						   list->cipher_aux,
						   false))
			goto nextloop;

		if (!acvp_list_cipher_match_key(keylen, list->keylen))
			goto nextloop;


		if (print_deps) {
			if (strlen(list->impl))
				acvp_extend_string(impl, sizeof(impl), "%s%s",
						   strlen(impl) ? ", ": "",
						   list->impl);
			if (strlen(list->external_dep))
				acvp_extend_string(external_dep,
						   sizeof(external_dep),
						   "%s%s",
						   strlen(external_dep) ?
						   ", ": "",
						   list->external_dep);
			if (strlen(list->internal_dep))
				acvp_extend_string(internal_dep,
						   sizeof(internal_dep),
						   "%s%s",
						   strlen(internal_dep) ?
						   ", ": "",
						   list->internal_dep);
			}

		list->listed = true;

nextloop:
		/*
		 * We reached the end of the list but not all entries
		 * were processed - rewind.
		 */
		if (!list->next && !complete) {
			complete = true;
			cipher_name = NULL;
			cipher_mode = NULL;
			cipher_aux = NULL;
			list = full_list;

			/* Print */
			if (print_deps) {
				if (print) {
					fprintf(stdout, "%-*s | ", *im_len,
						impl);
					fprintf(stdout, "%-*s | ", *ex_len,
						external_dep);
					fprintf(stdout, "%-*s", *in_len,
						internal_dep);
				} else {
					acvp_list_cipher_maxlen(im_len, impl);
					acvp_list_cipher_maxlen(ex_len,
								external_dep);
					acvp_list_cipher_maxlen(in_len,
								internal_dep);
				}
			}
			memset(&impl, 0, sizeof(impl));
			memset(&internal_dep, 0, sizeof(internal_dep));
			memset(&external_dep, 0, sizeof(external_dep));

			if (print)
				fprintf(stdout, "\n");
		}
	}

out:
	return ret;
}

static int
acvp_list_cipher_options_print(struct acvp_list_ciphers *full_list,
			       bool print_deps)
{
	struct acvp_list_ciphers *list;
	unsigned int ca_len = 0, cm_len = 0, cd_len = 0, ks_len = 0,
		     im_len = 0, ex_len = 0, in_len = 0;
	int ret;

	/* Get string lengths */
	CKINT(_acvp_list_cipher_options_print(full_list, print_deps,
					      &ca_len, &cm_len,
					      &cd_len, &ks_len, &im_len,
					      &ex_len, &in_len));

	/* Unset the listed field */
	for (list = full_list; list != NULL; list = list->next)
		list->listed = false;

	/* Print */
	if (print_deps) {
		fprintf(stdout, "%-*s | %-*s | %-*s | %-*s | %-*s | %-*s | %s\n",
			ca_len, "Algorithm",
			cm_len, "Mode",
			cd_len, "Details",
			ks_len, "Key Size",
			im_len, "Implementation",
			ex_len, "External Dependency",
			"Internal Dependency");
	} else {
		fprintf(stdout, "%-*s | %-*s | %-*s | %s\n",
			ca_len, "Algorithm",
			cm_len, "Mode",
			cd_len, "Details",
			"Key Size");
	}

	CKINT(_acvp_list_cipher_options_print(full_list, print_deps,
					      &ca_len, &cm_len,
					      &cd_len, &ks_len, &im_len,
					      &ex_len, &in_len));
out:
	return ret;
}

DSO_PUBLIC
int acvp_list_cipher_options(const struct acvp_ctx *ctx, bool list_deps)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	struct definition *def;
	struct acvp_list_ciphers *full_list = NULL;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	datastore = &ctx->datastore;
	search = &datastore->search;

	/* Find a module definition */
	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	while (def) {
		CKINT(acvp_list_cipher_options_prepare(def, &full_list));

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

	acvp_list_cipher_options_print(full_list, list_deps);

out:
	acvp_list_ciphers_free(full_list);
	return ret;
}
