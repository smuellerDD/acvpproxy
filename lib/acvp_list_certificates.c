/*
 * Copyright (C) 2019 - 2020, Stephan Mueller <smueller@chronox.de>
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
#include "mutex_w.h"
#include "request_helper.h"
#include "term_colors.h"

static DEFINE_MUTEX_W_UNLOCKED(acvp_list_cert_mutex);

struct acvp_list_cert_uniq {
	struct acvp_list_cert_uniq *next;
	char *cipher_name;
	char *cipher_mode;
	char *certificate;
	bool listed;
};
static struct acvp_list_cert_uniq *acvp_list_cert_uniq = NULL;

static int acvp_list_certificates_cb(const struct acvp_ctx *ctx,
				     const struct definition *def,
				     const uint32_t testid)
{
	const struct def_info *def_info;
	struct acvp_testid_ctx testid_ctx;
	struct acvp_auth_ctx *auth;
	int ret;

	def_info = def->info;

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

	fprintf(stdout, "%-50s | %-8u | %-10s\n",
		def_info->module_name, testid,
		auth->testsession_certificate_number);

out:
	acvp_release_auth(&testid_ctx);
	return ret;
}

static int acvp_store_cert_sorted(struct acvp_test_verdict_status *verdict,
				  const char *certificate)
{
	struct acvp_list_cert_uniq *new, *list = acvp_list_cert_uniq;
	int ret;

	CKNULL(certificate, -EINVAL);

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
			if (!strncmp(list->cipher_name,
				     verdict->cipher_name,
				     strlen(list->cipher_name)) &&
			    !strncmp(list->cipher_mode,
				     verdict->cipher_mode,
				     strlen(list->cipher_mode))) {
				ret = -EAGAIN;
				goto out;
			}
		} else {
			if (!strncmp(list->cipher_name,
				     verdict->cipher_name,
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
	CKINT(acvp_duplicate(&new->certificate, certificate));

	if (!acvp_list_cert_uniq) {
		acvp_list_cert_uniq = new;
	} else {
		struct acvp_list_cert_uniq *prev = acvp_list_cert_uniq;

		CKNULL_LOG(list, -EFAULT,
			   "Programming bug in acvp_list_cert_unique\n");

		/* Sorting */
		for (list = acvp_list_cert_uniq;
		     list != NULL;
		     list = list->next) {

			/*
			 * Sort the certificate numbers for given certificate
			 * name in ascending order
			 */
			if (acvp_find_match(list->cipher_name,
					    new->cipher_name, false) &&
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
		ACVP_PTR_FREE_NULL(list->certificate);
		list = list->next;
		ACVP_PTR_FREE_NULL(tmp);
	}

	acvp_list_cert_uniq = NULL;
}

static int acvp_get_cert_detail_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				     const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_vsid_ctx tmp_ctx;
	struct acvp_test_verdict_status *verdict;
	int ret;

	(void)buf;

	memcpy(&tmp_ctx, vsid_ctx, sizeof(tmp_ctx));
	CKINT(ds->acvp_datastore_get_vsid_verdict(&tmp_ctx));

	verdict = &tmp_ctx.verdict;

	/* Ensure that a given name/mode combo is only listed once */
	ret = acvp_store_cert_sorted(verdict,
				     auth->testsession_certificate_number);
	if (ret == -EAGAIN)
		return 0;

out:
	return ret;
}

static int acvp_get_cert_details_cb(const struct acvp_ctx *ctx,
				    const struct definition *def,
				    const uint32_t testid)
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

static int acvp_list_cert_details(void)
{
	struct acvp_list_cert_uniq *list;
	const char *cipher_name = NULL, *cipher_mode = NULL;
	int ret = 0;
	bool complete = true;

	mutex_w_lock(&acvp_list_cert_mutex);

	for (list = acvp_list_cert_uniq; list != NULL; list = list->next) {
		complete &= list->listed;

		/* Skip an already processed list entry */
		if (list->listed)
			goto nextloop;

		/* We have a fresh new cipher name */
		if (!cipher_name) {
			cipher_name = list->cipher_name;
			cipher_mode = list->cipher_mode;

			fprintf(stdout, " * %s", cipher_name);
			if (cipher_mode)
				fprintf(stdout, " (%s)", cipher_mode);

			fprintf(stdout, " - Cert. #%s", list->certificate);

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
	return ret;
}

DSO_PUBLIC
int acvp_list_certificates(const struct acvp_ctx *ctx)
{
	fprintf(stdout, "%-50s | %-8s | %-10s\n",
		"Module Name", "Test ID", "Certificate No");
	return acvp_process_testids(ctx, &acvp_list_certificates_cb);
}

DSO_PUBLIC
int acvp_list_certificates_detailed(const struct acvp_ctx *ctx)
{
	int ret;

	fprintf(stderr, "processing database ");
	CKINT(acvp_process_testids(ctx, &acvp_get_cert_details_cb));
	fprintf(stderr, "\n");
	CKINT(acvp_list_cert_details());

out:
	return ret;
}
