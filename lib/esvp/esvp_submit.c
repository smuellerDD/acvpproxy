/* Registering of entropy source and submit of data
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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
#include "hash/sha256.h"
#include "threading_support.h"

#include <json-c/json.h>

/***************************************************************************/

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
				     json_object_new_int((int)cc->min_h_in)));
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
esvp_process_datafiles_post_one(const struct acvp_testid_ctx *testid_ctx,
				const char *url, const char *pathname,
				char *data_type,
				struct acvp_ext_buf *additional_keys)
{
	struct stat statbuf;
	ACVP_EXT_BUFFER_INIT(data);
	ACVP_BUFFER_INIT(response);
	int ret, ret2, fd;

	if (stat(pathname, &statbuf))
		return -errno;

	if (S_ISREG(statbuf.st_mode))
		return -EINVAL;

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

	data.len = (uint32_t)statbuf.st_size;
	data.data_type = data_type;
	data.next = additional_keys;

	/* Send the data to the ESVP server. */
	/* TODO shall we do anything with the response buffer? */
	ret2 = acvp_net_op(testid_ctx, url, &data, &response,
			   acvp_http_post_multi);

	CKINT(acvp_request_error_handler(ret2));

	munmap(data.buf, (size_t)statbuf.st_size);
	close(fd);

out:
	acvp_free_buf(&response);
	return ret;
}

static int esvp_process_datafiles_post(const struct acvp_testid_ctx *testid_ctx)
{
	const struct esvp_es_def *es = testid_ctx->es_def;
	const struct esvp_cc_def *cc;
	ACVP_EXT_BUFFER_INIT(itar);
	ACVP_EXT_BUFFER_INIT(desc);
	char pathname[FILENAME_MAX], url[ACVP_NET_URL_MAXLEN];
	int ret;

	/* Post the raw noise data file */
	snprintf(pathname, sizeof(pathname), "%s/%s/%s%s", es->config_dir,
		 ESVP_ES_DIR_RAW_NOISE, ESVP_ES_FILE_RAW_NOISE,
		 ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->raw_noise_id));
	CKINT(esvp_process_datafiles_post_one(testid_ctx, url, pathname,
					      "datafile", NULL));

	/* Post the restart data file */
	snprintf(pathname, sizeof(pathname), "%s/%s/%s%s", es->config_dir,
		 ESVP_ES_DIR_RAW_NOISE, ESVP_ES_FILE_RESTART_DATA,
		 ESVP_ES_BINARY_FILE_EXTENSION);
	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT, url,
				  sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
				 testid_ctx->testid, NIST_ESVP_VAL_OP_DATAFILE,
				 es->restart_id));
	CKINT(esvp_process_datafiles_post_one(testid_ctx, url, pathname,
					      "datafile", NULL));

	/* Post all conditioning component files */
	for (cc = es->cc; cc; cc = cc->next) {
		snprintf(pathname, sizeof(pathname), "%s/%s%s", cc->config_dir,
			 ESVP_ES_FILE_CC_DATA, ESVP_ES_BINARY_FILE_EXTENSION);
		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_ENTROPY_ASSESSMENT,
					  url, sizeof(url)),
			  "Creation of request URL failed\n");
		CKINT(acvp_extend_string(url, sizeof(url), "/%u/%s/%u",
					 testid_ctx->testid,
					 NIST_ESVP_VAL_OP_DATAFILE, cc->cc_id));
		CKINT(esvp_process_datafiles_post_one(testid_ctx, url, pathname,
						      "datafile", NULL));
	}

	DIR *doc_dir;
	struct dirent *doc_dirent;
	char doc_dir_name[FILENAME_MAX - 256];

	//TODO make this configurable
	snprintf(doc_dir_name, sizeof(doc_dir_name), "%s/%s",
		 ACVP_DEF_DEFAULT_CONFIG_DIR, ESVP_ES_DIR_DOCUMENTATION);

	doc_dir = opendir(doc_dir_name);
	CKNULL_LOG(doc_dir, -errno, "Failed to open directory %s\n",
		   doc_dir_name);

	itar.buf = (uint8_t *)(es->itar ? "true" : "false");
	itar.len = es->itar ? 4 : 5;
	itar.data_type = "itar";
	itar.next = &desc;
	desc.data_type = "sdComments";

	while ((doc_dirent = readdir(doc_dir)) != NULL) {
		if (!acvp_usable_dirent(doc_dirent, NULL))
			continue;

		snprintf(pathname, sizeof(pathname), "%s/%s", doc_dir_name,
			 doc_dirent->d_name);

		desc.buf = (uint8_t *)doc_dirent->d_name;
		desc.len = (uint32_t)strlen(doc_dirent->d_name);

		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_SUPPDOC, url,
					  sizeof(url)),
			  "Creation of request URL failed\n");
		CKINT(esvp_process_datafiles_post_one(testid_ctx, url, pathname,
						      "sdFile", &itar));
	}

out:
	return ret;
}

static int esvp_process_datafiles(const struct acvp_testid_ctx *testid_ctx,
				  struct json_object *entry)
{
	struct json_object *data_urls, *found_json;
	struct esvp_es_def *es = testid_ctx->es_def;
	struct esvp_cc_def *cc;
	const char *str;
	unsigned int seq_no = 1;
	int ret;

	/* TODO store the IDs for reentrant operations */
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
		CKINT(esvp_datafiles_find(data_urls, "conditionedBits", 0,
					  &found_json));
		CKINT(json_get_string(found_json, "conditionedBits", &str));
		CKINT(acvp_get_trailing_number(str, &cc->cc_id));
	}

	CKINT(esvp_process_datafiles_post(testid_ctx));

out:
	return ret;
}

static int esvp_process_req(struct acvp_testid_ctx *testid_ctx,
			    struct json_object *request,
			    struct acvp_buf *response)
{
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

	/* Store access token in ctx */
	CKINT_LOG(acvp_set_authtoken(testid_ctx, jwt),
		  "Cannot set the new JWT token\n");

	/* Download the testvectors */
	CKINT_LOG(esvp_process_datafiles(testid_ctx, entry),
		  "Cannot obtain test vectors\n");

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
	const struct esvp_es_def *es = testid_ctx->es_def;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct json_object *request = NULL;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKINT_LOG(acvp_init_auth(testid_ctx),
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

out:
	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response_buf);
	return ret;
}

/***************************************************************************/

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
