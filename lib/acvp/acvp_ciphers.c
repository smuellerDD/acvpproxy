/* ACVP proxy protocol handler for retrieving the cipher specification
 *
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>
#include <sys/stat.h>

#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"

/* GET /algorithms */
static int acvp_fetch_cipher_info(const struct acvp_testid_ctx *testid_ctx,
				  const uint32_t algoid, struct acvp_buf *buf)
{
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	CKINT(acvp_create_url(NIST_VAL_OP_ALGORITHMS, url, sizeof(url)));

	if (algoid < UINT_MAX)
		CKINT(acvp_extend_string(url, sizeof(url), "/%u", algoid));

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL: %s\n", url);

	CKINT(acvp_process_retry_testid(testid_ctx, buf, url));

out:
	return ret;
}

static int acvp_iterate_algoarray(const struct acvp_testid_ctx *testid_ctx,
				  struct json_object *response,
				  const char *ciphername, const char *pathname)
{
	struct json_object *algorithms;
	FILE *file = NULL;
	ACVP_BUFFER_INIT(buf);
	unsigned int i;
	int ret;
	char prevname[30];

	memset(prevname, 0, sizeof(prevname));

	CKINT(json_find_key(response, "algorithms", &algorithms,
			    json_type_array));

	/*
	 * Process:
	 * {
	 *   "algorithms" : [ {
	 *   "url" : "/acvp/v1/algorithms/2",
	 *   "name" : "AES-CBC",
	 *   "revision" : "1.0"
	 * }, {
	 *   "url" : "/acvp/v1/algorithms/7",
	 *   "name" : "AES-CCM",
	 *   "revision" : "1.0"
	 * }, {
	 *   ...
	 */
	for (i = 0; i < (uint32_t)json_object_array_length(algorithms); i++) {
		struct json_object *algo =
			json_object_array_get_idx(algorithms, i);
		struct stat statbuf;
		const char *url, *algoname;
		uint32_t urlnum;
		char jsonfile[FILENAME_MAX], tmpalgoname[256];

		if (!json_object_is_type(algo, json_type_object)) {
			json_logger(LOGGER_WARN, LOGGER_C_ANY, algo,
				    "JSON value is no object");
			ret = -EINVAL;
			goto out;
		}

		CKINT(json_get_string(algo, "name", &algoname));

		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Received algorithm information for %s\n", algoname);

		if (ciphername && !strstr(algoname, ciphername))
			continue;

		if (!pathname) {
			const char *mode;

			ret = json_get_string(algo, "mode", &mode);
			if (ret) {
				fprintf(stdout, "%s\n", algoname);
				ret = 0;
			} else {
				fprintf(stdout, "%s %s\n", algoname, mode);
			}
			continue;
		}

		/* Get details about cipher */
		/* Get "algorithm ID" */
		ret = json_get_string(algo, "url", &url);
		if (ret) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY, "No detailed cipher information available for algorithm %s\n", algoname);
			continue;
		}
		CKINT(acvp_get_trailing_number(url, &urlnum));

		snprintf(tmpalgoname, sizeof(tmpalgoname), "%s", algoname);
		CKINT(acvp_req_check_filename(tmpalgoname,
					      strlen(tmpalgoname)));

		/* Write the data */
		snprintf(jsonfile, sizeof(jsonfile), "%s/%s-%u.json", pathname,
			 tmpalgoname, urlnum);

		/* Do not re-download information */
		if (!stat(jsonfile, &statbuf)) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "Detailed cipher option information for %s already downloaded, skipping new download\n",
			       algoname);
			logger_status(
				LOGGER_C_ANY,
				"Detailed cipher option information for %s already downloaded, skipping new download\n",
				algoname);

			/* implement "touch" */
			file = fopen(jsonfile, "a");
			if (file)
				fclose(file);
			file = NULL;

			continue;
		}

		/* Fetch details about the algorithm ID */
		CKINT(acvp_fetch_cipher_info(testid_ctx, urlnum, &buf));

		file = fopen(jsonfile, "w");
		CKNULL_LOG(file, -errno, "Failed to open file %s\n", jsonfile);

		fwrite(buf.buf, 1, buf.len, file);

		fclose(file);
		file = NULL;
		acvp_free_buf(&buf);
	}

out:
	if (file)
		fclose(file);
	acvp_free_buf(&buf);
	return ret;
}

DSO_PUBLIC
int acvp_cipher_get(const struct acvp_ctx *ctx, const char *ciphername[],
		    const size_t ciphername_arraylen, const char *pathname)
{
	struct acvp_testid_ctx testid_ctx;
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(buf);
	size_t i;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL,
		   "Vendor validation: authentication context missing\n");

	memset(&testid_ctx, 0, sizeof(testid_ctx));
	CKINT(acvp_init_auth(&testid_ctx));
	testid_ctx.ctx = ctx;

	CKINT(acvp_fetch_cipher_info(&testid_ctx, UINT_MAX, &buf));

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(&buf, &req, &entry));

	if (ciphername_arraylen) {
		for (i = 0; i < ciphername_arraylen; i++)
			CKINT(acvp_iterate_algoarray(&testid_ctx, entry,
						     ciphername[i], pathname));
	} else {
		CKINT(acvp_iterate_algoarray(&testid_ctx, entry, NULL,
					     pathname));
	}

out:
	acvp_free_buf(&buf);
	acvp_release_auth(&testid_ctx);
	ACVP_JSON_PUT_NULL(req);

	return ret;
}
