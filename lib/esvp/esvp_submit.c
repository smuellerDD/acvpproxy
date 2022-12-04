/* Registering of entropy source and submit of data
 *
 * Copyright (C) 2021 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esvpproxy.h"
#include "binhexbin.h"
#include "esvp_internal.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "sleep.h"
#include "threading_support.h"

#include <json-c/json.h>

/***************************************************************************
 * Registration handling
 ***************************************************************************/

static int esvp_register_build_cc(const struct esvp_cc_def *cc,
				  unsigned int sequence_no,
				  struct json_object *cc_array)
{
	struct json_object *cc_entry;
	int ret;

	CKNULL(cc, -EINVAL);

	cc_entry = json_object_new_object();
	CKNULL(cc_entry, -ENOMEM);
	CKINT(json_object_array_add(cc_array, cc_entry));

	CKINT(json_object_object_add(cc_entry, "sequencePosition",
				     json_object_new_int((int)sequence_no)));
	CKINT(json_object_object_add(cc_entry, "description",
				     json_object_new_string(cc->description)));
	CKINT(json_object_object_add(cc_entry, "vetted",
				     json_object_new_boolean(cc->vetted)));
	if (!cc->vetted) {
		CKINT(json_object_object_add(
			cc_entry, "bijectiveClaim",
			json_object_new_boolean(cc->bijective)));
		CKINT(json_add_bin2hex(cc_entry, "conditionedBitsSHA256",
				       &cc->data_hash));
	} else {
		cipher_t cipher;

		/* Check that the description points to one ACVTS cipher name */
		ret = acvp_req_name_to_cipher(cc->description, &cipher);
		if (ret) {
			char *ciphers;

			CKINT(acvp_req_all_cipher_to_stringarray(&ciphers));

			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "For a vetted conditioning component the description must refer to one of the follwing strings indicating the used cipher: %s\n",
			       ciphers);
			ret = -EINVAL;
			goto out;
		}

		CKINT(json_object_object_add(
			cc_entry, "validationNumber",
			json_object_new_string(cc->acvts_certificate)));
	}
	CKINT(json_object_object_add(cc_entry, "minNin",
				     json_object_new_int((int)cc->min_n_in)));
	CKINT(json_object_object_add(cc_entry, "minHin",
				     json_object_new_double(cc->min_h_in)));
	CKINT(json_object_object_add(cc_entry, "nw",
				     json_object_new_int((int)cc->nw)));
	CKINT(json_object_object_add(cc_entry, "nOut",
				     json_object_new_int((int)cc->n_out)));

out:
	return ret;
}

static int esvp_register_build(const struct esvp_es_def *es,
			       struct json_object *request)
{
	struct json_object *entry, *cc_array;
	struct esvp_cc_def *cc;
	unsigned int seq_no = 1;
	int ret;

	/* Array entry for version */
	CKINT(acvp_req_add_version(request));

	/* Array entry for request */
	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(request, entry));

	CKINT(json_object_object_add(
		entry, "primaryNoiseSource",
		json_object_new_string(es->primary_noise_source_desc)));
	CKINT(json_object_object_add(entry, "iidClaim",
				     json_object_new_boolean(es->iid)));
	CKINT(json_object_object_add(
		entry, "bitsPerSample",
		json_object_new_int((int)es->bits_per_sample)));
	CKINT(json_object_object_add(
		entry, "alphabetSize",
		json_object_new_int((int)es->alphabet_size)));
	CKINT(json_object_object_add(
		entry, "hminEstimate",
		json_object_new_double(es->h_min_estimate)));
	CKINT(json_object_object_add(entry, "physical",
				     json_object_new_boolean(es->physical)));
	CKINT(json_object_object_add(entry, "itar",
				     json_object_new_boolean(es->itar)));
	CKINT(json_add_bin2hex(entry, "rawNoiseSHA256",
			       &es->raw_noise_data_hash));
	CKINT(json_object_object_add(
		entry, "numberOfRestarts",
		json_object_new_int((int)es->raw_noise_number_restarts)));
	CKINT(json_object_object_add(
		entry, "samplesPerRestart",
		json_object_new_int((int)es->raw_noise_samples_restart)));
	CKINT(json_add_bin2hex(entry, "restartBitsSHA256",
			       &es->raw_noise_restart_hash));
	CKINT(json_object_object_add(
		entry, "additionalNoiseSources",
		json_object_new_boolean(es->additional_noise_sources)));

	if (!es->cc)
		goto out;

	cc_array = json_object_new_array();
	CKNULL(cc_array, -ENOMEM);
	CKINT(json_object_object_add(entry, "conditioningComponent", cc_array));

	for (cc = es->cc; cc; cc = cc->next, seq_no++) {
		CKINT(esvp_register_build_cc(cc, seq_no, cc_array));
	}

out:
	return ret;
}

static int esvp_datafiles_find(struct json_object *data_urls, const char *key,
			       unsigned int seq_no,
			       struct json_object **found_json)
{
	unsigned int i;
	int ret = 0;

	CKNULL(data_urls, -EINVAL);

	*found_json = NULL;

	for (i = 0; i < json_object_array_length(data_urls); i++) {
		struct json_object *tmp,
			*url = json_object_array_get_idx(data_urls, i);

		CKNULL(url, EINVAL);

		if (!json_object_object_get_ex(url, key, &tmp))
			continue;

		if (seq_no) {
			unsigned int val;

			ret = json_get_uint(url, "sequencePosition", &val);
			if (ret) {
				ret = 0;
				continue;
			}

			if (seq_no != val)
				continue;
		}
		*found_json = url;
		break;
	}

	if (!*found_json)
		ret = -ENOENT;

out:
	return ret;
}

static int
esvp_process_post_one_response(const struct acvp_testid_ctx *testid_ctx,
			       const struct acvp_buf *response,
			       const char *pathname)
{
	struct json_object *req = NULL, *entry = NULL;
	const char *str;
	int ret;

	(void)testid_ctx;
	(void)pathname;

	if (!response->buf || !response->len) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "No response data found\n");
		return 0;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find ESVP response\n");

	CKINT(json_get_string(entry, "status", &str));
	if (strncmp(str, "success", 7)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ESVP server returned error %s during uploading of file\n",
		       str);
		ret = -EINVAL;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(req);

	if (ret < 0 && ret != -EINTR && ret != -ESHUTDOWN) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot process server request %d:\n %s\n", ret,
		       response->buf);
	}
	return ret;
}

static int
esvp_process_post_one_sd_response(const struct acvp_testid_ctx *testid_ctx,
				  const struct acvp_buf *response,
				  const char *pathname)
{
	struct esvp_sd_file_def *file = NULL, *file_new;
	struct esvp_es_def *es = testid_ctx->es_def;
	struct esvp_sd_def *sd = NULL;
	struct json_object *req = NULL, *entry = NULL;
	const char *str;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "No response data found\n");
		return 0;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find ESVP response\n");

	CKINT(json_get_string(entry, "status", &str));
	if (strncmp(str, "success", 7)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ESVP server returned error %s during uploading of file\n",
		       str);
		ret = -EINVAL;
		goto out;
	}

	/* Did we already submit it? */
	for (sd = es->sd; sd; sd = sd->next) {
		bool found = false;

		file = sd->file;
		while (file) {
			if (!strncmp(file->filename, pathname,
				     strlen(file->filename))) {
				found = true;
				break;
			}

			file = file->next;
		}

		if (found)
			break;
	}

	if (!sd) {
		sd = calloc(1, sizeof(struct esvp_sd_def));
		CKNULL(sd, -ENOMEM);
	}

	/* Get access token */
	CKINT(json_get_string(entry, "accessToken", &str));
	/* Store access token in ctx */
	if (!sd->sd_auth)
		CKINT(acvp_init_acvp_auth_ctx(&sd->sd_auth));
	CKINT_LOG(acvp_set_authtoken_temp(sd->sd_auth, str),
		  "Cannot set the new JWT token\n");

	CKINT(json_get_uint(entry, "sdId", &sd->sd_id));

	file_new = calloc(1, sizeof(struct esvp_sd_file_def));
	CKNULL(file_new, -ENOMEM);

	if (!sd->file) {
		sd->file = file_new;
	} else {
		file = sd->file;
		while (file->next)
			file = file->next;

		file->next = file_new;
	}

	CKINT(acvp_duplicate(&file_new->filename, pathname));
	file_new->submitted = true;

	/*
	 * Append the new conditioning component entry at the end of the list
	 * because the order matters.
	 */
	if (es->sd) {
		struct esvp_sd_def *iter_sd = es->sd;

		while (iter_sd) {
			/*
			 * In case the SD is already registered,
			 * do not do it again
			 */
			if (iter_sd == sd)
				break;

			if (!iter_sd->next) {
				iter_sd->next = sd;
				break;
			}
			iter_sd = iter_sd->next;
		}
	} else {
		es->sd = sd;
	}

	CKINT(esvp_write_status(testid_ctx));

out:
	ACVP_JSON_PUT_NULL(req);

	if (ret)
		esvp_def_sd_free(sd);

	if (ret < 0 && ret != -EINTR && ret != -ESHUTDOWN) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot process server request %d:\n %s\n", ret,
		       response->buf);
	}
	return ret;
}

/* POST multi */
static int esvp_process_datafiles_post_one(
	const struct acvp_testid_ctx *testid_ctx, const char *url,
	char *pathname, bool *submitted, char *data_type,
	struct acvp_ext_buf *additional_keys,
	int (*proces_response)(const struct acvp_testid_ctx *testid_ctx,
			       const struct acvp_buf *response,
			       const char *pathname))
{
	struct esvp_es_def *es = testid_ctx->es_def;
	struct esvp_sd_def *sd;
	struct stat statbuf;
	ACVP_EXT_BUFFER_INIT(data);
	ACVP_BUFFER_INIT(response);
	int ret, ret2, fd;

	if (submitted && *submitted) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Data found in %s already submitted, no resubmit\n",
		       pathname);
		return 0;
	}

	/* Check whether supporting document file has been uploaded */
	for (sd = es->sd; sd; sd = sd->next) {
		struct esvp_sd_file_def *file = sd->file;

		while (file) {
			if (!acvp_str_match(file->filename, pathname,
					    testid_ctx->testid)) {
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Data found in %s already submitted, no resubmit\n",
				       pathname);
				return 0;
			}

			file = file->next;
		}
	}

	if (stat(pathname, &statbuf)) {
		int errsv = errno;

		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Accessing file %s failed (stat error code %d)\n",
		       pathname, errsv);
		return -errsv;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "File %s is not a regular file\n", pathname);
		return -EINVAL;
	}

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;

		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "Cannot open file %s (%d)\n", pathname, ret);
		goto out;
	}

	data.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED,
			fd, 0);
	if (data.buf == MAP_FAILED) {
		logger(LOGGER_WARN, LOGGER_C_DS_FILE, "Cannot mmap file %s\n",
		       pathname);
		ret = -ENOMEM;
		goto out;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Posting file %s\n", pathname);
	data.len = (uint32_t)statbuf.st_size;
	data.data_type = data_type;
	data.filename = basename(pathname);
	data.next = additional_keys;

	logger_status(LOGGER_C_ANY, "Submitting file %s\n", pathname);

	/* Send the data to the ESVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &data, &response,
			   acvp_http_post_multi);

	ret = acvp_request_error_handler(ret2);

	munmap(data.buf, (size_t)statbuf.st_size);
	close(fd);

	if (ret)
		goto out;

	CKINT(proces_response(testid_ctx, &response, pathname));

	if (submitted)
		*submitted = true;

	CKINT(esvp_write_status(testid_ctx));

out:
	acvp_free_buf(&response);
	return ret;
}


static int
esvp_process_get_datafile_info(const struct acvp_testid_ctx *testid_ctx,
			       const struct acvp_buf *response,
			       const char *type)
{
	struct json_object *req = NULL, *entry = NULL;
	char pathname[FILENAME_MAX];
	const char *str;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "No response data found\n");
		return -EFAULT;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find ESVP response\n");

	snprintf(pathname, sizeof(pathname), "%s-entropy-rate.json", type);
	CKINT(acvp_store_file(testid_ctx, response, 1, pathname));

	CKINT(json_get_string(entry, "status", &str));
	if (!strncmp(str, "RunStarted", 10)) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server crunching numbers on raw data for %s\n",
			      type);
		ret = -EAGAIN;
		goto out;
	} else if (!strncmp(str, "Uploaded", 8)) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server crunching numbers on raw data for %s\n",
			      type);
		ret = -EAGAIN;
		goto out;
	} else if (!strncmp(str, "Initial", 7)) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server crunching numbers on raw data for %s\n",
			      type);
		ret = -EAGAIN;
		goto out;
	} else if (!strncmp(str, "RunSuccessful", 13)) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server finished calculating the entropy rate for %s - success\n",
			      type);
		ret = 0;
		goto out;
	} else {
		logger_status(LOGGER_C_ANY,
			      "ESVP server finished calculating the entropy rate for %s - failure\n",
			      type);
		ret = -EFAULT;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

/* GET /<raw noise files> */
static int _esvp_get_datafile_info(struct acvp_testid_ctx *testid_ctx)
{
	struct esvp_es_def *es = testid_ctx->es_def;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	/* Get the status on the raw noise data file */
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->raw_noise_id));

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Getting status on raw entropy data\n");

	/* Send the data to the ESVP server. */
	ret2 = acvp_net_op(testid_ctx, url, NULL, &response, acvp_http_get);
	CKINT(acvp_request_error_handler(ret2));
	ret = esvp_process_get_datafile_info(testid_ctx, &response,
					     "raw_noise");
	if (ret && ret != -EAGAIN)
		goto out;
	acvp_free_buf(&response);

	/* Get the status on the restart noise data file */
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->restart_id));

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Getting status on raw entropy data\n");

	/* Send the data to the ESVP server. */
	ret2 = acvp_net_op(testid_ctx, url, NULL, &response, acvp_http_get);
	CKINT(acvp_request_error_handler(ret2));
	ret2 = esvp_process_get_datafile_info(testid_ctx, &response,
					      "restart");
	if (ret2 && ret2 != -EAGAIN) {
		ret = ret2;
		goto out;
	}

	ret |= ret2;

out:
	acvp_free_buf(&response);
	return ret;
}

static int esvp_get_datafile_info(struct acvp_testid_ctx *testid_ctx)
{
	int ret = 0;

#define ESVP_GET_DATAFILE_INFO_SLEEPTIME 30
	do {
		/* Wait the requested amount of seconds */
		if (ret) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "ESVP server needs more time - sleeping for %u seconds for testID %u again\n",
			       ESVP_GET_DATAFILE_INFO_SLEEPTIME,
			       testid_ctx->testid);
			CKINT(sleep_interruptible(
				ESVP_GET_DATAFILE_INFO_SLEEPTIME,
				&acvp_op_interrupted));
		}

		ret = _esvp_get_datafile_info(testid_ctx);
	} while (ret == -EAGAIN);

out:
	return ret;
}

static int esvp_process_datafiles_post(struct acvp_testid_ctx *testid_ctx)
{
	struct esvp_es_def *es = testid_ctx->es_def;
	struct esvp_cc_def *cc;
	struct esvp_sd_def *sd;
	DIR *doc_dir = NULL;
	struct dirent *doc_dirent;
	ACVP_EXT_BUFFER_INIT(itar);
	ACVP_EXT_BUFFER_INIT(desc);
	ACVP_EXT_BUFFER_INIT(sdtype);
	char doc_dir_name[FILENAME_MAX - 256], pathname[FILENAME_MAX],
		url[ACVP_NET_URL_MAXLEN];
	int ret;

	/* Post the raw noise data file */
	snprintf(pathname, sizeof(pathname), "%s/%s/%s%s", es->config_dir,
		 ESVP_ES_DIR_ENTROPY_SOURCE, ESVP_ES_FILE_RAW_NOISE,
		 ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->raw_noise_id));
	CKINT_LOG(esvp_process_datafiles_post_one(
			  testid_ctx, url, pathname, &es->raw_noise_submitted,
			  "dataFile", NULL, esvp_process_post_one_response),
		  "Cannot post raw noise data\n");

	/* Post the restart data file */
	snprintf(pathname, sizeof(pathname), "%s/%s/%s%s", es->config_dir,
		 ESVP_ES_DIR_ENTROPY_SOURCE, ESVP_ES_FILE_RESTART_DATA,
		 ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->restart_id));
	CKINT_LOG(esvp_process_datafiles_post_one(
			  testid_ctx, url, pathname, &es->restart_submitted,
			  "dataFile", NULL, esvp_process_post_one_response),
		  "Cannot post restart noise data\n");

	/* Post all conditioning component files */
	for (cc = es->cc; cc; cc = cc->next) {
		/* Only process non-vetted conditioning components */
		if (cc->vetted)
			continue;

		snprintf(pathname, sizeof(pathname), "%s/%s%s", cc->config_dir,
			 ESVP_ES_FILE_CC_DATA, ESVP_ES_BINARY_FILE_EXTENSION);
		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT,
					  url, sizeof(url)),
			  "Creation of request URL failed\n");
		CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
					 testid_ctx->testid,
					 NIST_ESVP_VAL_OP_DATAFILE, cc->cc_id));
		CKINT(esvp_process_datafiles_post_one(
			testid_ctx, url, pathname, &cc->output_submitted,
			"dataFile", NULL, esvp_process_post_one_response));
	}

	snprintf(doc_dir_name, sizeof(doc_dir_name), "%s/%s", es->config_dir,
		 ESVP_ES_DIR_DOCUMENTATION);

	doc_dir = opendir(doc_dir_name);
	CKNULL_LOG(doc_dir, -errno, "Failed to open directory %s\n",
		   doc_dir_name);

	itar.buf = (uint8_t *)(es->itar ? "true" : "false");
	itar.len = es->itar ? 4 : 5;
	itar.data_type = "isITAR";
	itar.next = &desc;
	desc.data_type = "sdComments";

	sdtype.data_type = "sdType";
	desc.next = &sdtype;

	while ((doc_dirent = readdir(doc_dir)) != NULL) {
		bool submitted = false;

		if (!acvp_usable_dirent(doc_dirent, NULL))
			continue;

		snprintf(pathname, sizeof(pathname), "%s/%s", doc_dir_name,
			 doc_dirent->d_name);

		/* Did we already submit it? */
		for (sd = es->sd; sd; sd = sd->next) {
			struct esvp_sd_file_def *file = sd->file;

			while (file) {
				if (!strncmp(file->filename, pathname,
					     strlen(file->filename))) {
					submitted = file->submitted;
					break;
				}

				file = file->next;
			}

			if (submitted)
				break;
		}

		desc.buf = (uint8_t *)doc_dirent->d_name;
		desc.len = (uint32_t)strlen(doc_dirent->d_name);

		if (!strncasecmp(doc_dirent->d_name, "entropy-analysis", 16) ||
		    !strncasecmp(doc_dirent->d_name, "entropy_analysis", 16) ||
		    !strncasecmp(doc_dirent->d_name, "entropyanalysis", 15) ||
		    !strncasecmp(doc_dirent->d_name, "ear", 3)) {
			sdtype.buf = (uint8_t *)"EntropyAnalysisReport";
			sdtype.len = 21;
		} else if (strstr(doc_dirent->d_name, "public") ||
			   strstr(doc_dirent->d_name, "Public") ||
			   strstr(doc_dirent->d_name, "PUBLIC")) {
			sdtype.buf = (uint8_t *)"PublicUseDocument";
			sdtype.len = 17;
		} else {
			sdtype.buf = (uint8_t *)"Other";
			sdtype.len = 5;
		}

		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_SUPPDOC, url,
					  sizeof(url)),
			  "Creation of request URL failed\n");

		CKINT(esvp_process_datafiles_post_one(
			testid_ctx, url, pathname, &submitted, "sdFile", &itar,
			esvp_process_post_one_sd_response));
	}

out:
	if (doc_dir)
		closedir(doc_dir);
	return ret;
}

static int esvp_process_datafiles(struct acvp_testid_ctx *testid_ctx,
				  struct json_object *entry)
{
	struct json_object *data_urls, *found_json;
	struct esvp_es_def *es = testid_ctx->es_def;
	struct esvp_cc_def *cc;
	const char *str;
	unsigned int seq_no = 1;
	int ret;

	CKINT(json_find_key(entry, "dataFileUrls", &data_urls,
			    json_type_array));

	CKINT(esvp_datafiles_find(data_urls, "rawNoiseBits", 0, &found_json));
	CKINT(json_get_string(found_json, "rawNoiseBits", &str));
	CKINT(acvp_get_trailing_number(str, &es->raw_noise_id));

	CKINT(esvp_datafiles_find(data_urls, "restartTestBits", 0,
				  &found_json));
	CKINT(json_get_string(found_json, "restartTestBits", &str));
	CKINT(acvp_get_trailing_number(str, &es->restart_id));

	for (cc = es->cc; cc; cc = cc->next, seq_no++) {
		/* Only process non-vetted conditioning components */
		if (cc->vetted)
			continue;

		CKINT(esvp_datafiles_find(data_urls, "conditionedBits", seq_no,
					  &found_json));
		CKINT(json_get_string(found_json, "conditionedBits", &str));
		CKINT(acvp_get_trailing_number(str, &cc->cc_id));
	}

	CKINT(esvp_process_datafiles_post(testid_ctx));

out:
	return ret;
}

/******************************************************************************
 * General processing
 ******************************************************************************/
static int esvp_process_req(struct acvp_testid_ctx *testid_ctx,
			    struct json_object *request,
			    struct acvp_buf *response)
{
	const struct esvp_es_def *es = testid_ctx->es_def;
	struct json_object *req = NULL, *entry = NULL;
	const char *jwt;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find ESVP response\n");

	/* Extract testID URL and ID number */
	CKINT_LOG(acvp_get_testid(testid_ctx, request, entry),
		  "Cannot get testID from ESVP server response\n");

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, ESVP_DS_TESTIDMETA,
					      true, response));

	/* Get access token */
	CKINT_LOG(json_get_string(entry, "accessToken", &jwt),
		  "ESVP server response does not contain expected JWT\n");

	/* Store access token in ctx without writing it to disk */
	CKINT_LOG(acvp_set_authtoken_temp(testid_ctx->server_auth, jwt),
		  "Cannot set the new JWT token\n");
	CKINT(acvp_copy_auth(es->es_auth, testid_ctx->server_auth));

	CKINT(esvp_write_status(testid_ctx));

	/* Store the definition search criteria */
	CKINT_LOG(acvp_export_def_search(testid_ctx),
		  "Cannot store the search criteria\n");

	/* Upload the data */
	CKINT_LOG(esvp_process_datafiles(testid_ctx, entry),
		  "Cannot submit data files\n");

	/* Get the status information on the raw data */
	CKINT_LOG(esvp_get_datafile_info(testid_ctx),
		  "Cannot get status information on raw data\n");

	CKINT_LOG(esvp_certify(testid_ctx), "Cannot certify\n");

out:
	ACVP_JSON_PUT_NULL(req);

	if (ret < 0 && ret != -EINTR && ret != -ESHUTDOWN) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot process server request %d:\n %s\n", ret,
		       response->buf);
	}

	return ret;
}

/* POST /entropyAssessments */
static int esvp_register_op(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	struct esvp_es_def *es = testid_ctx->es_def;
	struct json_object *request = NULL;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKNULL(ctx, -EFAULT);
	req_details = &ctx->req_details;

	CKINT_LOG(acvp_init_auth(testid_ctx),
		  "Failure to initialize authtoken\n");
	CKINT_LOG(acvp_init_acvp_auth_ctx(&es->es_auth),
		  "Failure to initialize authtoken\n");

	request = json_object_new_array();
	CKNULL(request, -ENOMEM);

	CKINT(esvp_register_build(es, request));

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				request,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");

	/* Send the entropy source request to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);
	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	/* Process the response and download the vectors. */
	CKINT(esvp_process_req(testid_ctx, request, &response_buf));

	logger_status(LOGGER_C_ANY,
		      "Check at a later time with esvp-proxy --testid %u for status updates\n",
		      testid_ctx->testid);

out:
	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response_buf);
	return ret;
}

static int esvp_continue_op(struct acvp_testid_ctx *testid_ctx)
{
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	CKINT(acvp_init_auth(testid_ctx));

	testid_ctx->status_parse = esvp_read_status;

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Refresh all auth tokens including ES and SD tokens */
	CKINT(acvp_login_refresh(testid_ctx));

	/* Write potentially changed auth tokens */
	CKINT(esvp_write_status(testid_ctx));

	/* Check if all files are uploaded and retry if not */
	CKINT_LOG(esvp_process_datafiles_post(testid_ctx),
		  "Cannot submit data files\n");

	CKINT(esvp_process_datafiles_post(testid_ctx));

	/* Get the status information on the raw data */
	CKINT_LOG(esvp_get_datafile_info(testid_ctx),
		  "Cannot get status information on raw data\n");

	CKINT_LOG(esvp_certify(testid_ctx), "Cannot certify\n");

out:
	acvp_release_auth(testid_ctx);

	return ret;
}

/******************************************************************************
 * APIs
 ******************************************************************************/

static int esvp_init_testid_ctx(struct acvp_testid_ctx *testid_ctx,
				const struct acvp_ctx *ctx,
				const struct definition *def,
				struct esvp_es_def *es_def,
				const uint32_t testid)
{
	int ret;

	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));
	testid_ctx->es_def = es_def;

out:
	return ret;
}

static int esvp_process_one_es(const struct acvp_ctx *ctx,
			       const struct definition *def, uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	struct esvp_es_def *es = def->es;
	int ret;

	(void)testid;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);
	CKINT(esvp_init_testid_ctx(testid_ctx, ctx, def, es, 0));

	CKINT(esvp_register_op(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int esvp_register(const struct acvp_ctx *ctx)
{
	return acvp_register_cb(ctx, &esvp_process_one_es);
}

static int _esvp_continue(const struct acvp_ctx *ctx,
			  const struct definition *def, const uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	struct esvp_es_def *es = def->es;
	int ret;

	(void)testid;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);
	CKINT(esvp_init_testid_ctx(testid_ctx, ctx, def, es, testid));

	CKINT(esvp_continue_op(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int esvp_continue(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx));

	CKINT(acvp_process_testids(ctx, &_esvp_continue));

out:
	return ret;
}
