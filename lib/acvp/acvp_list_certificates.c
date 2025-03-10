/* Listing of locally stored certificates with various output formats
 *
 * Copyright (C) 2019 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include <unistd.h>

#include "acvpproxy.h"
#include "definition_internal.h"
#include "internal.h"
#include "json_wrapper.h"
#include "mutex_w.h"
#include "request_helper.h"
#include "term_colors.h"

static DEFINE_MUTEX_W_UNLOCKED(acvp_list_cert_mutex);

struct acvp_list_cert_uniq {
	struct acvp_list_cert_uniq *next;
	char *cipher_name;
	char *cipher_mode;
	char *impl_name;
	char *certificate;
	bool listed;
};
static struct acvp_list_cert_uniq *acvp_list_cert_uniq = NULL;

static int acvp_list_certificates_cb(const struct acvp_ctx *ctx,
				     const struct definition *def,
				     const uint64_t testid)
{
	const struct def_info *def_info;
	const struct def_oe *def_oe;
	const struct def_dependency *def_dep;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	def_info = def->info;
	def_oe = def->oe;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	if (!auth->testsession_certificate_number)
		goto out;

	fprintf(stdout, "%-44s", def_info->module_name);

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name)
			fprintf(stdout, "- %-10s", def_dep->name);
		if (def_dep->proc_name)
			fprintf(stdout, "- %-10s", def_dep->proc_name);
	}

	fprintf(stdout, " | %-8"PRIu64" | %-10s\n", testid,
		auth->testsession_certificate_number);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_list_missing_certificates_cb(const struct acvp_ctx *ctx,
					     const struct definition *def,
					     const uint64_t testid)
{
	const struct def_info *def_info;
	const struct def_oe *def_oe;
	const struct def_dependency *def_dep;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	def_info = def->info;
	def_oe = def->oe;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	if (auth->testsession_certificate_number)
		goto out;

	fprintf(stdout, "%-44s", def_info->module_name);

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name)
			fprintf(stdout, "- %-10s", def_dep->name);
		if (def_dep->proc_name)
			fprintf(stdout, "- %-10s", def_dep->proc_name);
	}
	fprintf(stdout, " | %-8"PRIu64"\n", testid);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_process_one_vsid_results(const struct acvp_vsid_ctx *vsid_ctx,
					 const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct definition *def = testid_ctx->def;
	const struct def_info *def_info = def->info;
	const struct def_oe *def_oe = def->oe;
	const struct def_dependency *def_dep;

	(void)buf;

	if (vsid_ctx->response_file_present)
		return 0;

	fprintf(stdout, "%-44s", def_info->module_name);

	for (def_dep = def_oe->def_dep; def_dep; def_dep = def_dep->next) {
		if (def_dep->name)
			fprintf(stdout, "- %-10s", def_dep->name);
		if (def_dep->proc_name)
			fprintf(stdout, "- %-10s", def_dep->proc_name);
	}
	fprintf(stdout, " | %-8"PRIu64"\n", vsid_ctx->vsid);

	return 0;
}

static int acvp_list_missing_results_cb(const struct acvp_ctx *ctx,
					const struct definition *def,
					const uint64_t testid)
{
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	testid_ctx.def = def;
	testid_ctx.ctx = ctx;
	testid_ctx.testid = testid;
	CKINT(acvp_init_auth(&testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(&testid_ctx));

	/* Get testsession ID */
	auth = testid_ctx.server_auth;

	CKINT(ds->acvp_datastore_find_responses(&testid_ctx,
						acvp_process_one_vsid_results));

	if (auth->testsession_certificate_number)
		goto out;

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_store_cert_sorted(const struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_test_verdict_status *verdict = &vsid_ctx->verdict;
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	const struct definition *def = testid_ctx->def;
	const struct def_info *def_info = def->info;
	const char *certificate = auth->testsession_certificate_number;
	struct acvp_list_cert_uniq *new, *list = acvp_list_cert_uniq;
	int ret;

	CKNULL(certificate, -EINVAL);

	if (!verdict->cipher_name) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Something is wrong with vsID %"PRIu64" - no cipher name! Ignoring.\n",
		       vsid_ctx->vsid);
		return 0;
	}

	mutex_w_lock(&acvp_list_cert_mutex);

	fprintf(stderr, ".");

	/* Remove duplications */
	while (list) {
		/* Duplication check only applies to same certificate */
		if (strncmp(certificate, list->certificate,
			    strlen(list->certificate))) {
			if (!list->next)
				break;
			list = list->next;
			continue;
		}
		if (verdict->cipher_mode) {
			if (!strncmp(list->cipher_name, verdict->cipher_name,
				     strlen(list->cipher_name)) &&
			    !strncmp(list->cipher_mode, verdict->cipher_mode,
				     strlen(list->cipher_mode))) {
				ret = -EAGAIN;
				goto out;
			}
		} else {
			if (!strncmp(list->cipher_name, verdict->cipher_name,
				     strlen(list->cipher_name))) {
				ret = -EAGAIN;
				goto out;
			}
		}
		if (!list->next)
			break;
		list = list->next;
	}

	new = calloc(1, sizeof(struct acvp_list_cert_uniq));
	CKNULL(new, -ENOMEM);
	CKINT(acvp_duplicate(&new->cipher_mode, verdict->cipher_mode));
	CKINT(acvp_duplicate(&new->cipher_name, verdict->cipher_name));
	CKINT(acvp_duplicate(&new->impl_name, def_info->impl_name));
	CKINT(acvp_duplicate(&new->certificate, certificate));

	if (!acvp_list_cert_uniq) {
		acvp_list_cert_uniq = new;
	} else {
		struct acvp_list_cert_uniq *prev = acvp_list_cert_uniq;

		CKNULL_LOG(list, -EFAULT,
			   "Programming bug in acvp_list_cert_unique\n");

		/* Sorting */
		for (list = acvp_list_cert_uniq; list != NULL;
		     list = list->next) {
			/*
			 * Sort the certificate numbers for given certificate
			 * name in ascending order
			 */
			if (acvp_find_match(list->cipher_name, new->cipher_name,
					    false) &&
			    (strncasecmp(list->certificate, new->certificate,
					 strlen(list->certificate)) > 0)) {
				if (list == acvp_list_cert_uniq)
					acvp_list_cert_uniq = new;
				else
					prev->next = new;

				new->next = list;
				break;
			}

			/* Sort cipher name in ascending order. */
			if ((strncasecmp(list->cipher_name, new->cipher_name,
					 strlen(list->cipher_name)) > 0)) {
				if (list == acvp_list_cert_uniq)
					acvp_list_cert_uniq = new;
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
	}

out:
	mutex_w_unlock(&acvp_list_cert_mutex);
	return ret;
}

static void acvp_list_cert_unique_free(void)
{
	struct acvp_list_cert_uniq *list = acvp_list_cert_uniq;

	while (list) {
		struct acvp_list_cert_uniq *tmp = list;

		ACVP_PTR_FREE_NULL(list->cipher_mode);
		ACVP_PTR_FREE_NULL(list->cipher_name);
		ACVP_PTR_FREE_NULL(list->impl_name);
		ACVP_PTR_FREE_NULL(list->certificate);
		list = list->next;
		ACVP_PTR_FREE_NULL(tmp);
	}

	acvp_list_cert_uniq = NULL;
}

static int acvp_get_cert_detail_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				     const struct acvp_buf *buf)
{
	struct acvp_vsid_ctx tmp_ctx;
	int ret;

	(void)buf;

	memcpy(&tmp_ctx, vsid_ctx, sizeof(tmp_ctx));
	CKINT(ds->acvp_datastore_get_vsid_verdict(&tmp_ctx));

	/* Ensure that a given name/mode combo is only listed once */
	ret = acvp_store_cert_sorted(&tmp_ctx);
	if (ret == -EAGAIN)
		return 0;

out:
	return ret;
}

static int acvp_get_cert_details_cb(const struct acvp_ctx *ctx,
				    const struct definition *def,
				    const uint64_t testid)
{
	const struct def_info *def_info = def->info;
	struct acvp_testid_ctx *testid_ctx = NULL;
	struct acvp_auth_ctx *auth;
	int ret = 0;

	CKNULL_LOG(def, -EINVAL, "Definition data not defined\n");

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->testid = testid;
	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));
	auth = testid_ctx->server_auth;

	if (!auth->testsession_certificate_number) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Certificate not received yet for module %s\n",
		       def_info->module_name);
		return 0;
	}

	CKINT(ds->acvp_datastore_get_testid_verdict(testid_ctx));

	/* If there was no test response, we mark it accordingly. */
	if (!testid_ctx->verdict.verdict)
		testid_ctx->verdict.verdict = acvp_verdict_downloadpending;

	testid_ctx->verdict.cipher_mode = NULL;
	testid_ctx->verdict.cipher_name = NULL;

	CKINT(ds->acvp_datastore_find_responses(testid_ctx,
						acvp_get_cert_detail_vsid));

	/*
	 * We will get an EEXIST back due to the final call to
	 * acvp_datastore_find_testid_verdict in
	 * acvp_datastore_find_responses.
	 */
	ret = 0;

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);
	return ret;
}

static int acvp_list_cert_match_processed(struct json_object *entry,
					  const bool processed)
{
	struct json_object *bool_entry;
	int ret;

	/* Set or add a marker that this entry was processed. */
	ret = json_find_key(entry, "processed", &bool_entry, json_type_boolean);
	if (ret < 0) {
		ret = json_object_object_add(
			entry, "processed", json_object_new_boolean(processed));
	} else {
		ret = json_object_set_boolean(bool_entry, processed);
	}

	return ret;
}

/*
 * Match the cipher name / implementation against a JSON structure of
 * {
 *	"ECDSA": {
 *		"implementation": "vng_ltc",
 *		"mode": [ "sigVer", "sigGen" ]
 *	},
 *	"ACVP-AES-CBC": {
 *		"implementation": "c_ltc"
 *	},
 *	"SHA2-256": {
 *		"implementation": "vng_ltc"
 *	}
 * }
 */
static bool acvp_list_cert_match_ciphers(struct json_object *req_ciphers,
					 const char *impl_name,
					 const char *cipher_name,
					 const char *mode)
{
	struct json_object_iter one_cipher;
	struct json_object *array;
	int rc;
	const char *impl_search;
	bool ret = false;

	if (!req_ciphers)
		return true;

	/* Iterate over the one or more entries found in the configuration */
	json_object_object_foreachC(req_ciphers, one_cipher)
	{
		bool found = false;

		if (!json_object_is_type(one_cipher.val, json_type_object)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "JSON data type %s does not match expected type %s\n",
			       json_type_to_name(
				       json_object_get_type(one_cipher.val)),
			       json_type_to_name(json_type_string));
			goto out;
		}

		/* Match the cipher name */
		if (!acvp_find_match(cipher_name, one_cipher.key, true))
			continue;

		rc = json_get_string(one_cipher.val, "implementation",
				     &impl_search);
		if (rc < 0) {
			ret = false;
			goto out;
		}

		if (!acvp_find_match(impl_name, impl_search, false))
			continue;

		/* Match the implementation name and mode string */
		/* We allow this item to not exist */
		rc = json_find_key(one_cipher.val, "mode", &array,
				   json_type_array);
		if (rc == 0) {
			struct json_object *mode_def;
			unsigned int i;

			for (i = 0; i < json_object_array_length(array); i++) {
				const char *mode_search;

				mode_def = json_object_array_get_idx(array, i);
				if (!mode_def)
					break;
				if (!json_object_is_type(mode_def,
							 json_type_string)) {
					logger(LOGGER_ERR, LOGGER_C_ANY,
					       "Mode definition for %s contains data other than strings: %s\n",
					       one_cipher.key,
					       json_type_to_name(
						       json_object_get_type(
							       mode_def)));
					break;
				}

				mode_search = json_object_get_string(mode_def);
				if (acvp_find_match(mode, mode_search, false)) {
					found = true;
					break;
				}
			}

			/*
			 * TODO should we add a marker if a mode matching
			 * failed?
			 */
		} else {
			found = true;
		}

		if (!found)
			continue;

		/* Set or add a marker that this entry was processed. */
		rc = acvp_list_cert_match_processed(one_cipher.val, true);
		if (rc < 0) {
			ret = false;
			goto out;
		}
		ret = true;
		goto out;
	}

out:
	return ret;
}

/*
 * Check that all search definitions are processed.
 */
static int acvp_list_cert_match_used(struct json_object *req_ciphers)
{
	struct json_object_iter one_cipher;
	bool processed = false;
	bool first = false;
	int ret = 0;

	if (!req_ciphers)
		return 0;

	/* Iterate over the one or more entries found in the configuration */
	json_object_object_foreachC(req_ciphers, one_cipher)
	{
		ret = json_get_bool(one_cipher.val, "processed", &processed);
		if (ret || !processed) {
			const char *impl_search;

			if (!first) {
				fprintf(stdout,
					"Unprocessed matching definitions:\n");
				first = true;
			}
			CKINT(json_get_string(one_cipher.val, "implementation",
					      &impl_search));
			fprintf(stdout, "%s - %s\n", one_cipher.key,
				impl_search);
		}
	}

out:
	return ret;
}

static int acvp_list_cert_details(struct json_object *req_ciphers)
{
	struct acvp_list_cert_uniq *list;
	const char *cipher_name = NULL, *cipher_mode = NULL;
	int ret;
	bool complete = true;

	mutex_w_lock(&acvp_list_cert_mutex);

	for (list = acvp_list_cert_uniq; list != NULL; list = list->next) {
		complete &= list->listed;

		/* Skip an already processed list entry */
		if (list->listed)
			goto nextloop;

		/* We have a fresh new cipher name */
		if (!cipher_name) {
			/*
			 * Skip cipher definition if not defined in search
			 * criteria.
			 */
			if (!acvp_list_cert_match_ciphers(
				    req_ciphers, list->impl_name,
				    list->cipher_name, list->cipher_mode))
				continue;

			cipher_name = list->cipher_name;
			cipher_mode = list->cipher_mode;

			fprintf(stdout, " * %s", cipher_name);
			if (cipher_mode)
				fprintf(stdout, " (%s)", cipher_mode);

			fprintf(stdout, " - Cert. #%s", list->certificate);

			list->listed = true;
			goto nextloop;
		}

		/*
		 * Skip current certificate if it does not match search
		 * criteria.
		 */
		if (!acvp_list_cert_match_ciphers(req_ciphers, list->impl_name,
						  cipher_name, cipher_mode))
			goto nextloop;

		/* Only process entries with same cipher name / mode */
		if (!acvp_find_match(cipher_name, list->cipher_name, false))
			goto nextloop;
		if (cipher_mode &&
		    !acvp_find_match(cipher_mode, list->cipher_mode, false))
			goto nextloop;

		/* Print */
		fprintf(stdout, ", Cert. #%s", list->certificate);
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
			list = acvp_list_cert_uniq;
			fprintf(stdout, "\n\n");
		}
	}

	acvp_list_cert_unique_free();
	mutex_w_unlock(&acvp_list_cert_mutex);

	ret = acvp_list_cert_match_used(req_ciphers);

	return ret;
}

DSO_PUBLIC
int acvp_list_certificates(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-70s | %-8s | %-10s\n", "Module Name", "Test ID",
		"Certificate No");
	return acvp_process_testids(ctx, &acvp_list_certificates_cb);
}

DSO_PUBLIC
int acvp_list_missing_certificates(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-70s | %-8s\n", "Module Name", "Test ID");
	return acvp_process_testids(ctx, &acvp_list_missing_certificates_cb);
}

DSO_PUBLIC
int acvp_list_missing_results(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-70s | %-8s\n", "Module Name", "VectorSet ID");
	return acvp_process_testids(ctx, &acvp_list_missing_results_cb);
}

DSO_PUBLIC
int acvp_list_certificates_detailed(const struct acvp_ctx *ctx,
				    const char *req_ciphers_file)
{
	struct json_object *req_ciphers = NULL;
	int ret;

	if (req_ciphers_file) {
		req_ciphers = json_object_from_file(req_ciphers_file);
		CKNULL_LOG(req_ciphers, -EFAULT, "Cannot parse file %s (%s)\n",
			   req_ciphers_file, json_util_get_last_err());
		if (!json_object_is_type(req_ciphers, json_type_object)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "JSON input data in file %s is no object\n",
			       req_ciphers_file);
			ret = -EINVAL;
			goto out;
		}
	}

	fprintf(stderr, "processing database ");
	CKINT(acvp_process_testids(ctx, &acvp_get_cert_details_cb));
	fprintf(stderr, "\n");
	CKINT(acvp_list_cert_details(req_ciphers));

out:
	ACVP_JSON_PUT_NULL(req_ciphers);
	return ret;
}
